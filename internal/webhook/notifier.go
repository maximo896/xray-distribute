package webhook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/xray-distribute/internal/model"
)

// Notifier Webhook通知器
type Notifier struct {
	configs map[string]*model.WebhookConfig
	client  *http.Client
	logger  *slog.Logger
	mu      sync.RWMutex
	queue   chan *notifyJob
	wg      sync.WaitGroup
}

type notifyJob struct {
	vuln   *model.Vulnerability
	config *model.WebhookConfig
}

// NewNotifier 创建通知器
func NewNotifier(logger *slog.Logger) *Notifier {
	n := &Notifier{
		configs: make(map[string]*model.WebhookConfig),
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		logger: logger,
		queue:  make(chan *notifyJob, 1000),
	}

	// 启动通知worker
	for i := 0; i < 2; i++ {
		n.wg.Add(1)
		go n.worker()
	}

	return n
}

// AddConfig 添加Webhook配置
func (n *Notifier) AddConfig(cfg *model.WebhookConfig) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.configs[cfg.ID] = cfg
}

// RemoveConfig 移除Webhook配置
func (n *Notifier) RemoveConfig(id string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.configs, id)
}

// GetConfigs 获取所有配置
func (n *Notifier) GetConfigs() []*model.WebhookConfig {
	n.mu.RLock()
	defer n.mu.RUnlock()

	configs := make([]*model.WebhookConfig, 0, len(n.configs))
	for _, cfg := range n.configs {
		configs = append(configs, cfg)
	}
	return configs
}

// Notify 通知漏洞
func (n *Notifier) Notify(vuln *model.Vulnerability) {
	n.mu.RLock()
	defer n.mu.RUnlock()

	for _, cfg := range n.configs {
		if !cfg.Enabled {
			continue
		}

		job := &notifyJob{
			vuln:   vuln,
			config: cfg,
		}

		select {
		case n.queue <- job:
		default:
			n.logger.Warn("notify queue full, dropping", "webhook", cfg.Name)
		}
	}
}

// Stop 停止通知器
func (n *Notifier) Stop() {
	close(n.queue)
	n.wg.Wait()
}

// worker 处理通知
func (n *Notifier) worker() {
	defer n.wg.Done()

	for job := range n.queue {
		n.send(job)
	}
}

// send 发送Webhook通知
func (n *Notifier) send(job *notifyJob) {
	var payload interface{}

	switch job.config.Type {
	case "dingtalk":
		payload = n.buildDingTalkPayload(job.vuln)
	case "wecom":
		payload = n.buildWeComPayload(job.vuln)
	case "lark":
		payload = n.buildLarkPayload(job.vuln)
	case "custom":
		payload = n.buildCustomPayload(job.vuln, job.config.Template)
	default:
		payload = n.buildCustomPayload(job.vuln, "")
	}

	data, err := json.Marshal(payload)
	if err != nil {
		n.logger.Error("marshal webhook payload failed", "error", err)
		return
	}

	req, err := http.NewRequest("POST", job.config.URL, bytes.NewReader(data))
	if err != nil {
		n.logger.Error("create webhook request failed", "error", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	if job.config.Secret != "" {
		req.Header.Set("X-Webhook-Secret", job.config.Secret)
	}

	resp, err := n.client.Do(req)
	if err != nil {
		n.logger.Error("send webhook failed", "error", err, "url", job.config.URL)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		n.logger.Error("webhook response error", "status", resp.StatusCode, "url", job.config.URL)
		return
	}

	n.logger.Info("webhook sent", "type", job.config.Type, "vuln", job.vuln.Title)
}

// buildDingTalkPayload 构建钉钉通知
func (n *Notifier) buildDingTalkPayload(vuln *model.Vulnerability) map[string]interface{} {
	severityEmoji := map[string]string{
		"high":   "🔴",
		"medium": "🟡",
		"low":    "🟢",
		"info":   "⚪",
	}
	emoji := severityEmoji[vuln.Severity]

	text := fmt.Sprintf("%s **[XRay漏洞告警]**\n\n"+
		"**漏洞类型:** %s\n"+
		"**危险等级:** %s\n"+
		"**目标URL:** %s\n"+
		"**漏洞标题:** %s\n"+
		"**发现时间:** %s\n"+
		"**描述:** %s",
		emoji, vuln.VulnClass, vuln.Severity, vuln.URL, vuln.Title,
		vuln.CreatedAt.Format("2006-01-02 15:04:05"), truncate(vuln.Description, 200))

	return map[string]interface{}{
		"msgtype": "markdown",
		"markdown": map[string]string{
			"title": fmt.Sprintf("XRay漏洞告警 - %s", vuln.Title),
			"text":  text,
		},
	}
}

// buildWeComPayload 构建企业微信通知
func (n *Notifier) buildWeComPayload(vuln *model.Vulnerability) map[string]interface{} {
	content := fmt.Sprintf("【XRay漏洞告警】\n"+
		"漏洞类型: %s\n"+
		"危险等级: %s\n"+
		"目标URL: %s\n"+
		"漏洞标题: %s\n"+
		"发现时间: %s",
		vuln.VulnClass, vuln.Severity, vuln.URL, vuln.Title,
		vuln.CreatedAt.Format("2006-01-02 15:04:05"))

	return map[string]interface{}{
		"msgtype": "text",
		"text": map[string]string{
			"content": content,
		},
	}
}

// buildLarkPayload 构建飞书通知
func (n *Notifier) buildLarkPayload(vuln *model.Vulnerability) map[string]interface{} {
	severityColor := map[string]string{
		"high":   "red",
		"medium": "yellow",
		"low":    "green",
		"info":   "blue",
	}

	return map[string]interface{}{
		"msg_type": "interactive",
		"card": map[string]interface{}{
			"header": map[string]interface{}{
				"title": map[string]string{
					"tag":     "plain_text",
					"content": fmt.Sprintf("XRay漏洞告警 - %s", vuln.Title),
				},
				"template": severityColor[vuln.Severity],
			},
			"elements": []map[string]interface{}{
				{
					"tag": "div",
					"text": map[string]string{
						"tag":     "lark_md",
						"content": fmt.Sprintf("**漏洞类型:** %s\n**危险等级:** %s\n**目标URL:** %s\n**发现时间:** %s", vuln.VulnClass, vuln.Severity, vuln.URL, vuln.CreatedAt.Format("2006-01-02 15:04:05")),
					},
				},
			},
		},
	}
}

// buildCustomPayload 构建自定义通知
func (n *Notifier) buildCustomPayload(vuln *model.Vulnerability, template string) interface{} {
	if template != "" {
		// 简单模板替换
		t := strings.ReplaceAll(template, "{{.URL}}", vuln.URL)
		t = strings.ReplaceAll(t, "{{.Title}}", vuln.Title)
		t = strings.ReplaceAll(t, "{{.Severity}}", vuln.Severity)
		t = strings.ReplaceAll(t, "{{.VulnClass}}", vuln.VulnClass)
		t = strings.ReplaceAll(t, "{{.Description}}", vuln.Description)
		t = strings.ReplaceAll(t, "{{.Time}}", vuln.CreatedAt.Format("2006-01-02 15:04:05"))

		var result interface{}
		if err := json.Unmarshal([]byte(t), &result); err == nil {
			return result
		}
		return map[string]string{"text": t}
	}

	return map[string]interface{}{
		"vuln_id":     vuln.ID,
		"title":       vuln.Title,
		"severity":    vuln.Severity,
		"vuln_class":  vuln.VulnClass,
		"url":         vuln.URL,
		"description": vuln.Description,
		"request":     vuln.Request,
		"response":    vuln.Response,
		"created_at":  vuln.CreatedAt.Format(time.RFC3339),
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
