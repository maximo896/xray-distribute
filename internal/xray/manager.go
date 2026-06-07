package xray

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/xray-distribute/internal/model"
)

// Manager XRay进程管理器
type Manager struct {
	binary          string
	config          string // 原始配置文件路径
	dataDir         string
	listenAddr      string
	webhookURL      string
	level           string
	plugins         string
	logger          *slog.Logger
	mu              sync.RWMutex
	instance        *xrayInstance
	vulnChan        chan *model.Vulnerability
	generatedConfig string // interactsh生成的配置文件路径
}

// xrayInstance 运行中的XRay实例
type xrayInstance struct {
	cmd     *exec.Cmd
	cancel  context.CancelFunc
	pid     int
	status  string
	started time.Time
}

// NewManager 创建XRay管理器
func NewManager(binary, config, dataDir, listenAddr, webhookURL, level, plugins string, logger *slog.Logger) *Manager {
	// 将相对路径的binary转为绝对路径，避免设置cmd.Dir后找不到可执行文件
	if !filepath.IsAbs(binary) {
		if abs, err := filepath.Abs(binary); err == nil {
			binary = abs
		}
	}

	return &Manager{
		binary:     binary,
		config:     config,
		dataDir:    dataDir,
		listenAddr: listenAddr,
		webhookURL: webhookURL,
		level:      level,
		plugins:    plugins,
		logger:     logger,
		vulnChan:   make(chan *model.Vulnerability, 1000),
	}
}

// SetGeneratedConfig 设置interactsh生成的配置文件路径
func (m *Manager) SetGeneratedConfig(path string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.generatedConfig = path
}

// VulnChan 获取漏洞通道
func (m *Manager) VulnChan() <-chan *model.Vulnerability {
	return m.vulnChan
}

// Start 启动XRay被动扫描
// 使用 xray x --listen --webhook-output --html-output --json-output 等原生参数
func (m *Manager) Start(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.instance != nil && m.instance.status == "running" {
		return fmt.Errorf("xray instance already running (pid: %d)", m.instance.pid)
	}

	ctx, cancel := context.WithCancel(context.Background())

	timestamp := time.Now().Format("20060102_150405")

	// 构建xray命令参数
	args := []string{}
	configPath := m.generatedConfig
	if configPath == "" {
		configPath = m.config
	}
	if configPath != "" {
		if !filepath.IsAbs(configPath) {
			if abs, err := filepath.Abs(configPath); err == nil {
				configPath = abs
			}
		}
		args = append(args, "--config", configPath)
	}
	args = append(args, "webscan", "--listen", m.listenAddr)

	// HTML输出
	htmlOutput := filepath.Join(m.dataDir, fmt.Sprintf("xray_%s.html", timestamp))
	args = append(args, "--html-output", htmlOutput)

	// JSON输出
	jsonOutput := filepath.Join(m.dataDir, fmt.Sprintf("xray_%s.json", timestamp))
	args = append(args, "--json-output", jsonOutput)

	// Webhook输出 - xray原生POST漏洞JSON到指定URL
	if m.webhookURL != "" {
		args = append(args, "--webhook-output", m.webhookURL)
	}

	// 漏洞等级过滤
	if m.level != "" {
		args = append(args, "--level", m.level)
	}

	// 指定插件
	if m.plugins != "" {
		args = append(args, "--plugins", m.plugins)
	}

	m.logger.Info("starting xray", "args", args)

	cmd := exec.CommandContext(ctx, m.binary, args...)
	cmd.Dir = m.dataDir // 工作目录设为data目录，方便xray生成输出文件

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		cancel()
		return fmt.Errorf("start xray failed: %w", err)
	}

	instance := &xrayInstance{
		cmd:     cmd,
		cancel:  cancel,
		pid:     cmd.Process.Pid,
		status:  "running",
		started: time.Now(),
	}
	m.instance = instance

	// 监听XRay stdout（日志输出）
	go m.parseStdout(stdout)
	// 监听XRay stderr
	go m.parseStderr(stderr)
	// 监听进程退出
	go m.waitProcess()

	m.logger.Info("xray started",
		"pid", instance.pid,
		"listen", m.listenAddr,
		"html_output", htmlOutput,
		"json_output", jsonOutput,
		"webhook", m.webhookURL,
	)
	return nil
}

// Stop 停止XRay
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.instance == nil || m.instance.status != "running" {
		return fmt.Errorf("no running xray instance")
	}

	m.instance.cancel()
	if m.instance.cmd.Process != nil {
		m.instance.cmd.Process.Kill()
	}
	m.instance.status = "stopped"
	m.logger.Info("xray stopped", "pid", m.instance.pid)
	return nil
}

// Restart 重启XRay
func (m *Manager) Restart() error {
	if err := m.Stop(); err != nil {
		m.logger.Warn("stop xray warning", "error", err)
	}
	return m.Start("default")
}

// Status 获取XRay状态
func (m *Manager) Status() *model.XRayInstance {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.instance == nil {
		return &model.XRayInstance{Status: "stopped"}
	}

	return &model.XRayInstance{
		Status:    m.instance.status,
		Pid:       m.instance.pid,
		StartedAt: &m.instance.started,
	}
}

// SendToXRay 将镜像流量发送到XRay被动扫描端口
// XRay被动扫描通过HTTP代理方式接收流量
func (m *Manager) SendToXRay(req *model.MirrorRequest) error {
	m.mu.RLock()
	instance := m.instance
	m.mu.RUnlock()

	if instance == nil || instance.status != "running" {
		return fmt.Errorf("xray not running")
	}

	go func() {
		xrayReq, err := buildXRayRequest(req)
		if err != nil {
			m.logger.Error("build xray request failed", "error", err)
			return
		}

		// 通过XRay的被动扫描代理端口发送请求
		proxyURL, _ := url.Parse(fmt.Sprintf("http://%s", m.listenAddr))
		client := &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
			},
		}

		resp, err := client.Do(xrayReq)
		if err != nil {
			m.logger.Debug("send to xray failed", "error", err, "url", req.URL)
			return
		}
		resp.Body.Close()
	}()

	return nil
}

// HandleWebhook 处理XRay通过--webhook-output发送的漏洞数据
// XRay会POST JSON到指定URL，格式为标准xray漏洞输出
func (m *Manager) HandleWebhook(data json.RawMessage) {
	v := m.parseVulnFromRaw(data)
	if v != nil {
		select {
		case m.vulnChan <- v:
			m.logger.Info("vuln received via webhook",
				"severity", v.Severity,
				"title", v.Title,
				"url", v.URL)
		default:
			m.logger.Warn("vuln channel full, dropping")
		}
	}
}

// parseStdout 解析XRay stdout输出
func (m *Manager) parseStdout(reader io.Reader) {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		// 尝试解析为JSON漏洞数据（webhook之外的备用方案）
		var raw json.RawMessage
		if err := json.Unmarshal([]byte(line), &raw); err == nil {
			v := m.parseVulnFromRaw(raw)
			if v != nil {
				select {
				case m.vulnChan <- v:
				default:
				}
				continue
			}
		}
		// 普通日志
		m.logger.Debug("xray stdout", "msg", line)
	}
}

// parseStderr 解析XRay stderr
func (m *Manager) parseStderr(reader io.Reader) {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		m.logger.Debug("xray stderr", "msg", scanner.Text())
	}
}

// parseVulnFromRaw 从XRay JSON原始数据解析漏洞
// XRay webhook-output发送的JSON格式：
// {"type":"vuln/vuln_webhook","data":{"hash_id":"...","plugin":"...","url":"...",...}}
func (m *Manager) parseVulnFromRaw(raw json.RawMessage) *model.Vulnerability {
	var data map[string]interface{}
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil
	}

	// 检查type字段
	vulnType, _ := data["type"].(string)
	if vulnType != "vuln" && vulnType != "vuln_webhook" {
		return nil
	}

	vulnData, ok := data["data"].(map[string]interface{})
	if !ok {
		// 有些版本直接就是漏洞数据，没有data包装
		vulnData = data
	}

	v := &model.Vulnerability{
		ID:        fmt.Sprintf("%v", vulnData["hash_id"]),
		Plugin:    fmt.Sprintf("%v", vulnData["plugin"]),
		URL:       fmt.Sprintf("%v", vulnData["url"]),
		VulnClass: fmt.Sprintf("%v", vulnData["vuln_class"]),
		Title:     fmt.Sprintf("%v", vulnData["title"]),
		CreatedAt: time.Now(),
		Notified:  false,
	}

	// 解析detail
	if detail, ok := vulnData["detail"].(map[string]interface{}); ok {
		v.Severity = fmt.Sprintf("%v", detail["severity"])
		v.Description = fmt.Sprintf("%v", detail["description"])
		v.Solution = fmt.Sprintf("%v", detail["solution"])
	}

	// 如果detail中没有severity，尝试从顶层获取
	if v.Severity == "" {
		v.Severity = fmt.Sprintf("%v", vulnData["severity"])
	}

	// 解析request/response
	if req, ok := vulnData["request"].(string); ok {
		v.Request = req
	}
	if resp, ok := vulnData["response"].(string); ok {
		v.Response = resp
	}

	// 解析detail中的request/response（有些版本在这里）
	if v.Request == "" {
		if detail, ok := vulnData["detail"].(map[string]interface{}); ok {
			if req, ok := detail["request"].(string); ok {
				v.Request = req
			}
			if resp, ok := detail["response"].(string); ok {
				v.Response = resp
			}
		}
	}

	// 至少要有标题才算有效漏洞
	if v.Title == "" || v.Title == "<nil>" {
		return nil
	}

	return v
}

// waitProcess 等待进程退出
func (m *Manager) waitProcess() {
	if m.instance == nil || m.instance.cmd == nil {
		return
	}

	err := m.instance.cmd.Wait()

	m.mu.Lock()
	if m.instance != nil {
		if err != nil {
			m.instance.status = "error"
			m.logger.Error("xray process exited with error", "error", err)
		} else {
			m.instance.status = "stopped"
		}
	}
	m.mu.Unlock()
}

// buildXRayRequest 构建发送到XRay的HTTP请求
func buildXRayRequest(mr *model.MirrorRequest) (*http.Request, error) {
	var body io.Reader
	if len(mr.Body) > 0 {
		body = bytes.NewReader(mr.Body)
	}

	req, err := http.NewRequest(mr.Method, mr.URL, body)
	if err != nil {
		return nil, err
	}

	for key, values := range mr.Headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	return req, nil
}
