package xray

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
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

// Manager owns the passive xray process and keeps a small runtime log buffer.
type Manager struct {
	binary          string
	config          string
	dataDir         string
	listenAddr      string
	webhookURL      string
	level           string
	plugins         string
	logger          *slog.Logger
	mu              sync.RWMutex
	instance        *xrayInstance
	vulnChan        chan *model.Vulnerability
	generatedConfig string
	logs            []model.XRayLogEntry
	maxLogs         int
}

type xrayInstance struct {
	cmd     *exec.Cmd
	cancel  context.CancelFunc
	pid     int
	status  string
	started time.Time
	config  string
	html    string
	json    string
	err     string
}

func NewManager(binary, config, dataDir, listenAddr, webhookURL, level, plugins string, logger *slog.Logger) *Manager {
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
		logs:       make([]model.XRayLogEntry, 0, 300),
		maxLogs:    300,
	}
}

func (m *Manager) SetGeneratedConfig(path string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.generatedConfig = path
}

func (m *Manager) VulnChan() <-chan *model.Vulnerability {
	return m.vulnChan
}

func (m *Manager) Start(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.instance != nil && m.instance.status == "running" {
		return fmt.Errorf("xray instance already running (pid: %d)", m.instance.pid)
	}

	ctx, cancel := context.WithCancel(context.Background())
	timestamp := time.Now().Format("20060102_150405")

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

	htmlOutput := fmt.Sprintf("xray_%s.html", timestamp)
	jsonOutput := fmt.Sprintf("xray_%s.json", timestamp)
	args = append(args, "--html-output", htmlOutput, "--json-output", jsonOutput)

	if m.webhookURL != "" {
		args = append(args, "--webhook-output", m.webhookURL)
	}
	if m.level != "" {
		args = append(args, "--level", m.level)
	}
	if m.plugins != "" {
		args = append(args, "--plugins", m.plugins)
	}

	m.logger.Info("starting xray", "args", args)
	m.appendLogLocked("info", fmt.Sprintf("starting xray: %s %v", m.binary, args))

	cmd := exec.CommandContext(ctx, m.binary, args...)
	cmd.Dir = m.dataDir

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		cancel()
		m.appendLogLocked("error", fmt.Sprintf("start xray failed: %v", err))
		return fmt.Errorf("start xray failed: %w", err)
	}

	instance := &xrayInstance{
		cmd:     cmd,
		cancel:  cancel,
		pid:     cmd.Process.Pid,
		status:  "running",
		started: time.Now(),
		config:  configPath,
		html:    filepath.Join(m.dataDir, htmlOutput),
		json:    filepath.Join(m.dataDir, jsonOutput),
	}
	m.instance = instance

	go m.parseStdout(stdout)
	go m.parseStderr(stderr)
	go m.waitProcess()

	m.logger.Info("xray started",
		"pid", instance.pid,
		"listen", m.listenAddr,
		"html_output", htmlOutput,
		"json_output", jsonOutput,
		"webhook", m.webhookURL,
	)
	m.appendLogLocked("info", fmt.Sprintf("xray started, pid=%d, listen=%s", instance.pid, m.listenAddr))
	return nil
}

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
	m.appendLogLocked("info", fmt.Sprintf("xray stopped, pid=%d", m.instance.pid))
	return nil
}

func (m *Manager) Restart() error {
	if err := m.Stop(); err != nil {
		m.logger.Warn("stop xray warning", "error", err)
	}
	return m.Start("default")
}

func (m *Manager) Status() *model.XRayInstance {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.instance == nil {
		return &model.XRayInstance{
			Status:  "stopped",
			Listen:  m.listenAddr,
			Webhook: m.webhookURL,
		}
	}

	return &model.XRayInstance{
		Status:    m.instance.status,
		Pid:       m.instance.pid,
		Config:    m.instance.config,
		Listen:    m.listenAddr,
		Webhook:   m.webhookURL,
		HTMLFile:  m.instance.html,
		JSONFile:  m.instance.json,
		LastError: m.instance.err,
		StartedAt: &m.instance.started,
	}
}

func (m *Manager) Logs(limit int) []model.XRayLogEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if limit <= 0 || limit > len(m.logs) {
		limit = len(m.logs)
	}
	out := make([]model.XRayLogEntry, limit)
	copy(out, m.logs[len(m.logs)-limit:])
	return out
}

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
			m.addLog("error", fmt.Sprintf("build request failed: %v", err))
			m.logger.Error("build xray request failed", "error", err)
			return
		}

		proxyURL, _ := url.Parse(fmt.Sprintf("http://%s", m.listenAddr))
		client := &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, // xray是扫描器，不需要验证证书
				},
			},
		}

		resp, err := client.Do(xrayReq)
		if err != nil {
			m.addLog("error", fmt.Sprintf("send to xray failed: %s: %v", req.URL, err))
			m.logger.Debug("send to xray failed", "error", err, "url", req.URL)
			return
		}
		resp.Body.Close()
		m.addLog("info", fmt.Sprintf("sent to xray: %s %s", req.Method, req.URL))
	}()

	return nil
}

func (m *Manager) HandleWebhook(data json.RawMessage) {
	v := m.parseVulnFromRaw(data)
	if v != nil {
		select {
		case m.vulnChan <- v:
			m.addLog("warn", fmt.Sprintf("vulnerability: [%s] %s %s", v.Severity, v.Title, v.URL))
			m.logger.Info("vuln received via webhook",
				"severity", v.Severity,
				"title", v.Title,
				"url", v.URL)
		default:
			m.addLog("error", "vuln channel full, dropping")
			m.logger.Warn("vuln channel full, dropping")
		}
	}
}

func (m *Manager) parseStdout(reader io.Reader) {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		var raw json.RawMessage
		if err := json.Unmarshal([]byte(line), &raw); err == nil {
			v := m.parseVulnFromRaw(raw)
			if v != nil {
				select {
				case m.vulnChan <- v:
					m.addLog("warn", fmt.Sprintf("vulnerability: [%s] %s %s", v.Severity, v.Title, v.URL))
				default:
					m.addLog("error", "vuln channel full, dropping")
				}
				continue
			}
		}
		m.addLog("info", line)
		m.logger.Info("xray stdout", "msg", line)
	}
}

func (m *Manager) parseStderr(reader io.Reader) {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		m.addLog("error", line)
		m.logger.Warn("xray stderr", "msg", line)
	}
}

func (m *Manager) parseVulnFromRaw(raw json.RawMessage) *model.Vulnerability {
	var data map[string]interface{}
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil
	}

	vulnType, _ := data["type"].(string)
	if vulnType != "vuln" && vulnType != "vuln_webhook" && vulnType != "vuln/vuln_webhook" {
		return nil
	}

	vulnData, ok := data["data"].(map[string]interface{})
	if !ok {
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

	if detail, ok := vulnData["detail"].(map[string]interface{}); ok {
		v.Severity = fmt.Sprintf("%v", detail["severity"])
		v.Description = fmt.Sprintf("%v", detail["description"])
		v.Solution = fmt.Sprintf("%v", detail["solution"])
		if req, ok := detail["request"].(string); ok {
			v.Request = req
		}
		if resp, ok := detail["response"].(string); ok {
			v.Response = resp
		}
	}
	if v.Severity == "" || v.Severity == "<nil>" {
		v.Severity = fmt.Sprintf("%v", vulnData["severity"])
	}
	if req, ok := vulnData["request"].(string); ok {
		v.Request = req
	}
	if resp, ok := vulnData["response"].(string); ok {
		v.Response = resp
	}

	if v.Title == "" || v.Title == "<nil>" {
		return nil
	}
	return v
}

func (m *Manager) waitProcess() {
	m.mu.RLock()
	instance := m.instance
	m.mu.RUnlock()
	if instance == nil || instance.cmd == nil {
		return
	}

	err := instance.cmd.Wait()

	m.mu.Lock()
	if m.instance == instance {
		if err != nil {
			m.instance.status = "error"
			m.instance.err = err.Error()
			m.logger.Error("xray process exited with error", "error", err)
			m.appendLogLocked("error", fmt.Sprintf("xray process exited: %v", err))
		} else {
			m.instance.status = "stopped"
			m.appendLogLocked("info", "xray process exited")
		}
	}
	m.mu.Unlock()
}

func (m *Manager) addLog(level, message string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.appendLogLocked(level, message)
}

func (m *Manager) appendLogLocked(level, message string) {
	if message == "" {
		return
	}
	m.logs = append(m.logs, model.XRayLogEntry{
		Time:    time.Now(),
		Level:   level,
		Message: message,
	})
	if len(m.logs) > m.maxLogs {
		m.logs = m.logs[len(m.logs)-m.maxLogs:]
	}
}

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
