package reverse

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	interactshClient "github.com/projectdiscovery/interactsh/pkg/client"
	"github.com/projectdiscovery/interactsh/pkg/server"
	"gopkg.in/yaml.v3"

	"github.com/xray-distribute/internal/model"
)

/*
Manager 管理xray反连平台，支持两种模式：

模式1 - 本地模式 (mode: local):
  需要域名+DNS泛解析，xray进程内自带DNS/HTTP监听。
  适合有域名和VPS的场景。

模式2 - interactsh模式 (mode: interactsh):
  不需要域名，不需要开端口！使用interactsh公共服务器作为OOB回调平台。
  使用官方interactsh-client SDK，自动处理注册、URL生成、轮询和解密。
*/

// Manager 反连平台管理器
type Manager struct {
	binary  string // xray binary路径
	dataDir string
	config  ReverseConfig
	logger  *slog.Logger

	mu            sync.RWMutex
	running       bool
	adapterServer *http.Server
	adapterCancel context.CancelFunc

	// interactsh模式
	interactshClient *interactshClient.Client
	interactshURL    string // 生成的payload URL

	// 本地模式
	localCmd    *exec.Cmd
	localCancel context.CancelFunc

	// 交互记录存储（供API适配器查询）
	records     map[string][]OOBRecord // correlationID -> records
	recordsFile string
	recordsMu   sync.Mutex

	interactionChan chan model.OOBInteraction
}

// OOBRecord OOB交互记录
type OOBRecord struct {
	Protocol      string `json:"protocol"`
	FullID        string `json:"full_id"`
	RawRequest    string `json:"raw_request"`
	RawResponse   string `json:"raw_response"`
	RemoteAddress string `json:"remote_address"`
	Timestamp     int64  `json:"timestamp"`
}

// ReverseConfig 反连平台配置
type ReverseConfig struct {
	Enabled bool   `yaml:"enabled"`
	Mode    string `yaml:"mode"` // local 或 interactsh

	// 通用配置
	Token string `yaml:"token"`

	// 本地模式配置
	Domain   string `yaml:"domain"`
	ListenIP string `yaml:"listen_ip"`
	DNSPort  int    `yaml:"dns_port"`
	HTTPPort int    `yaml:"http_port"`
	DNSIsNS  bool   `yaml:"dns_is_ns"`

	// interactsh模式配置
	InteractshServer string `yaml:"interactsh_server"` // 公共interactsh服务器URL，默认 https://oast.fun
	InteractshToken  string `yaml:"interactsh_token"`  // interactsh服务器token（如果需要）

	// 适配器监听地址（interactsh模式下xray查询用）
	AdapterListen string `yaml:"adapter_listen"` // 默认 127.0.0.1:9900

	RecordingProxy string
}

// NewManager 创建反连平台管理器
func NewManager(binary string, dataDir string, cfg ReverseConfig, logger *slog.Logger) *Manager {
	// 将相对路径的binary转为绝对路径
	if !filepath.IsAbs(binary) {
		if abs, err := filepath.Abs(binary); err == nil {
			binary = abs
		}
	}
	if cfg.Enabled && cfg.Token == "" {
		cfg.Token = "xray-distribute-reverse-token"
	}
	m := &Manager{
		binary:          binary,
		dataDir:         dataDir,
		config:          cfg,
		logger:          logger,
		records:         make(map[string][]OOBRecord),
		interactionChan: make(chan model.OOBInteraction, 1000),
	}
	m.recordsFile = filepath.Join(m.dataDir, "oob_interactions.json")
	m.loadRecords()
	return m
}

// Start 启动反连平台
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.config.Enabled {
		m.logger.Info("reverse platform disabled")
		return nil
	}

	switch m.config.Mode {
	case "interactsh":
		return m.startInteractshMode()
	case "local":
		return m.startLocalMode()
	default:
		return fmt.Errorf("unknown reverse mode: %s (use 'local' or 'interactsh')", m.config.Mode)
	}
}

// Stop 停止反连平台
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.adapterCancel != nil {
		m.adapterCancel()
	}
	if m.adapterServer != nil {
		m.adapterServer.Close()
	}
	if m.localCancel != nil {
		m.localCancel()
	}
	if m.localCmd != nil && m.localCmd.Process != nil {
		m.localCmd.Process.Kill()
	}
	if m.interactshClient != nil {
		m.interactshClient.Close()
	}
	m.running = false
}

// IsRunning 是否运行中
func (m *Manager) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

// GetInteractshURL 获取interactsh生成的payload URL
func (m *Manager) GetInteractshURL() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.interactshURL
}

// startInteractshMode 启动interactsh模式（使用官方SDK）
func (m *Manager) startInteractshMode() error {
	serverURL := m.config.InteractshServer
	if serverURL == "" {
		serverURL = "https://oast.fun"
	}

	// 使用官方interactsh-client SDK
	client, err := interactshClient.New(&interactshClient.Options{
		ServerURL: serverURL,
		Token:     m.config.InteractshToken,
	})
	if err != nil {
		return fmt.Errorf("create interactsh client failed: %w", err)
	}

	m.interactshClient = client

	// 生成payload URL
	payloadURL := client.URL()
	m.interactshURL = payloadURL

	m.logger.Info("interactsh client registered",
		"payload_url", payloadURL,
		"server", serverURL)

	// 启动轮询
	err = client.StartPolling(5*time.Second, func(interaction *server.Interaction) {
		record := OOBRecord{
			Protocol:      interaction.Protocol,
			FullID:        interaction.FullId,
			RawRequest:    interaction.RawRequest,
			RawResponse:   interaction.RawResponse,
			RemoteAddress: interaction.RemoteAddress,
			Timestamp:     interaction.Timestamp.Unix(),
		}

		m.recordsMu.Lock()
		key := interaction.UniqueID
		m.records[key] = append(m.records[key], record)
		if len(m.records[key]) > 500 {
			m.records[key] = m.records[key][len(m.records[key])-500:]
		}
		m.saveRecordsLocked()
		m.recordsMu.Unlock()

		oob := model.OOBInteraction{
			Protocol:      record.Protocol,
			FullID:        record.FullID,
			RawRequest:    record.RawRequest,
			RawResponse:   record.RawResponse,
			RemoteAddress: record.RemoteAddress,
			Timestamp:     time.Unix(record.Timestamp, 0),
		}
		select {
		case m.interactionChan <- oob:
		default:
			m.logger.Warn("OOB interaction channel full, dropping notification", "full_id", record.FullID)
		}

		m.logger.Debug("OOB interaction received",
			"protocol", record.Protocol,
			"full_id", record.FullID,
			"remote", record.RemoteAddress)
	})
	if err != nil {
		client.Close()
		return fmt.Errorf("start interactsh polling failed: %w", err)
	}

	// 启动本地API适配器（供xray查询反连结果）
	adapterListen := m.adapterListen()
	if err := m.startAdapter(adapterListen); err != nil {
		client.Close()
		return fmt.Errorf("start adapter failed: %w", err)
	}

	m.running = true
	m.logger.Info("reverse platform started (interactsh mode)",
		"payload_url", payloadURL,
		"adapter", adapterListen)

	return nil
}

// startLocalMode 启动本地模式
func (m *Manager) startLocalMode() error {
	if m.config.Domain == "" {
		return fmt.Errorf("local mode requires a domain name")
	}

	// 启动 xray reverse 服务端
	ctx, cancel := context.WithCancel(context.Background())
	m.localCancel = cancel

	args := []string{"reverse"}
	if m.config.Token != "" {
		args = append(args, "--token", m.config.Token)
	}

	cmd := exec.CommandContext(ctx, m.binary, args...)
	cmd.Dir = m.dataDir

	if err := cmd.Start(); err != nil {
		cancel()
		return fmt.Errorf("start xray reverse server failed: %w", err)
	}
	m.localCmd = cmd

	go func() {
		cmd.Wait()
		m.mu.Lock()
		m.running = false
		m.mu.Unlock()
	}()

	m.running = true
	m.logger.Info("reverse platform started (local mode)",
		"domain", m.config.Domain)

	return nil
}

// startAdapter 启动本地API适配器
func (m *Manager) startAdapter(listenAddr string) error {
	ctx, cancel := context.WithCancel(context.Background())
	m.adapterCancel = cancel

	mux := http.NewServeMux()

	// xray reverse server API兼容端点
	mux.HandleFunc("/api/v1/reverse/", m.handleReverseQuery)
	mux.HandleFunc("/api/reverse/", m.handleReverseQuery)

	// 健康检查
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	m.adapterServer = &http.Server{
		Handler: mux,
	}

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}

	go func() {
		m.adapterServer.Serve(ln)
	}()

	go func() {
		<-ctx.Done()
		m.adapterServer.Close()
	}()

	return nil
}

// handleReverseQuery 处理xray的反连查询
// xray查询格式: GET /api/v1/reverse/?token=xxx&id=yyy
// id是xray生成的随机标识，interactsh的UniqueID格式为 {id}.{baseSubdomain}
// 所以需要前缀匹配
func (m *Manager) handleReverseQuery(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	id := r.URL.Query().Get("id")

	if m.config.Token != "" && token != m.config.Token {
		if r.Method == http.MethodPost && id == "" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"count": 0,
				"data":  []interface{}{},
			})
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	m.recordsMu.Lock()
	defer m.recordsMu.Unlock()

	// 先精确匹配
	var records []OOBRecord
	if recs, ok := m.records[id]; ok {
		records = recs
	} else {
		// 前缀匹配：xray的id可能是interactsh UniqueID的前缀
		// xray生成payload格式: {random_id}.{http_base_url}
		// interactsh UniqueID格式: {random_id}.{baseSubdomain}
		prefix := id + "."
		for key, recs := range m.records {
			if strings.HasPrefix(key, prefix) || key == id {
				records = append(records, recs...)
			}
		}
	}

	if len(records) == 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"count": 0,
			"data":  []interface{}{},
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"count": len(records),
		"data":  records,
	})
}

// GetXRayReverseConfig 生成xray配置文件中的Reverse段
func (m *Manager) GetXRayReverseConfig() *XRayReverseConfig {
	if !m.config.Enabled {
		return nil
	}

	cfg := &XRayReverseConfig{
		Token: m.config.Token,
	}

	if m.config.Mode == "interactsh" {
		adapterListen := m.adapterListen()

		// 从payload URL提取域名
		// payloadURL格式: xxx.oast.fun
		subdomain := m.interactshURL
		// 去掉协议前缀
		if len(subdomain) > 7 && subdomain[:7] == "http://" {
			subdomain = subdomain[7:]
		} else if len(subdomain) > 8 && subdomain[:8] == "https://" {
			subdomain = subdomain[8:]
		}
		// 去掉路径
		for i := 0; i < len(subdomain); i++ {
			if subdomain[i] == '/' {
				subdomain = subdomain[:i]
				break
			}
		}

		cfg.DBFilePath = "reverse.db"
		cfg.Client = XRayReverseClient{
			RemoteServer:     true,
			HTTPBaseURL:      fmt.Sprintf("http://%s", subdomain),
			ReverseServerURL: fmt.Sprintf("http://%s", adapterListen),
			ReverseAPI:       fmt.Sprintf("http://%s/api/v1/reverse/", adapterListen),
		}
		cfg.DNS = XRayReverseDNS{
			Enabled:  false,
			Domain:   subdomain,
			ListenIP: "127.0.0.1",
		}
		cfg.HTTP = XRayReverseHTTP{
			Enabled:  false,
			ListenIP: "127.0.0.1",
		}
	} else {
		dnsPort := m.config.DNSPort
		if dnsPort == 0 {
			dnsPort = 53
		}
		httpPort := m.config.HTTPPort
		if httpPort == 0 {
			httpPort = 80
		}

		cfg.DBFilePath = "reverse.db"
		cfg.Client = XRayReverseClient{
			RemoteServer: false,
			HTTPBaseURL:  fmt.Sprintf("http://%s:%d", m.config.ListenIP, httpPort),
		}
		cfg.DNS = XRayReverseDNS{
			Domain:             m.config.Domain,
			Enabled:            true,
			IsDomainNameServer: m.config.DNSIsNS,
			ListenIP:           m.config.ListenIP,
			Resolve: []XRayDNSResolve{
				{Record: "localhost", TTL: 60, Type: "A", Value: "127.0.0.1"},
			},
		}
		cfg.HTTP = XRayReverseHTTP{
			Enabled:    true,
			ListenIP:   m.config.ListenIP,
			ListenPort: fmt.Sprintf("%d", httpPort),
		}
	}

	cfg.RMI = XRayReverseRMI{
		Enabled:  false,
		ListenIP: "127.0.0.1",
	}

	return cfg
}

// GenerateXRayConfig 生成完整的xray配置文件
// 策略：读取 data/config.yaml（xray 4.0 格式），修改 reverse 部分，写回
func (m *Manager) GenerateXRayConfig(baseConfigPath string) (string, error) {
	if !m.config.Enabled {
		return baseConfigPath, nil
	}

	basePath := filepath.Join(m.dataDir, "config.yaml")
	configPath := filepath.Join(m.dataDir, "config.generated.yaml")

	// 读取已有的 config.yaml
	var config map[string]interface{}
	if data, err := os.ReadFile(basePath); err == nil {
		if err := yaml.Unmarshal(data, &config); err != nil {
			m.logger.Warn("parse existing config.yaml failed, will regenerate", "error", err)
			config = nil
		}
	}

	// 如果没有现成的 config.yaml，先让 xray 生成一份默认的
	if config == nil {
		m.logger.Info("no config.yaml found, generating default via xray")
		if err := m.generateDefaultConfig(); err != nil {
			return "", fmt.Errorf("generate default config failed: %w", err)
		}
		if data, err := os.ReadFile(basePath); err != nil {
			return "", fmt.Errorf("read generated config failed: %w", err)
		} else if err := yaml.Unmarshal(data, &config); err != nil {
			return "", fmt.Errorf("parse generated config failed: %w", err)
		}
	}

	// 构建 reverse 配置（xray 4.0 格式）
	delete(config, "version")
	reverseMap := m.buildReverseConfigV4()
	config["reverse"] = reverseMap
	if m.config.RecordingProxy != "" {
		httpCfg, ok := config["http"].(map[string]interface{})
		if !ok {
			httpCfg = make(map[string]interface{})
			config["http"] = httpCfg
		}
		httpCfg["proxy"] = m.config.RecordingProxy
	}

	// 修复 mitm 证书路径（xray 工作目录是 data/，证书在 data/certs/ 下，所以相对路径是 certs/ca.crt）
	if mitm, ok := config["mitm"].(map[string]interface{}); ok {
		mitm["ca_cert"] = filepath.Join("certs", "ca.crt")
		mitm["ca_key"] = filepath.Join("certs", "ca.key")
	}

	outputData, err := yaml.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("marshal config failed: %w", err)
	}
	outputData = append([]byte("version: 4.0\n"), outputData...)

	if err := os.WriteFile(configPath, outputData, 0644); err != nil {
		return "", fmt.Errorf("write config failed: %w", err)
	}

	m.logger.Info("generated xray config with reverse platform",
		"path", configPath,
		"mode", m.config.Mode,
		"payload_url", m.interactshURL)
	return configPath, nil
}

// generateDefaultConfig 通过运行 xray webscan 触发生成默认的 config.yaml
func (m *Manager) generateDefaultConfig() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// 运行 xray webscan 让它生成默认配置，然后立即终止
	cmd := exec.CommandContext(ctx, m.binary, "webscan", "--listen", "127.0.0.1:0", "--html-output", "default_gen.html")
	cmd.Dir = m.dataDir
	// 忽略输出和错误，xray 会生成 config.yaml 后因端口无效而退出
	_ = cmd.Run()

	// 检查是否生成了 config.yaml
	configPath := filepath.Join(m.dataDir, "config.yaml")
	if _, err := os.Stat(configPath); err != nil {
		return fmt.Errorf("config.yaml not generated after running xray")
	}
	return nil
}

// buildReverseConfigV4 构建 xray 4.0 格式的 reverse 配置
func (m *Manager) buildReverseConfigV4() map[string]interface{} {
	// xray工作目录是data/，所以db_file_path用相对于data/的路径
	reverse := map[string]interface{}{
		"db_file_path": "reverse.db",
		"token":        m.config.Token,
		"http": map[string]interface{}{
			"enabled":     false,
			"listen_ip":   "0.0.0.0",
			"listen_port": "",
			"ip_header":   "",
		},
		"dns": map[string]interface{}{
			"enabled":               false,
			"listen_ip":             "0.0.0.0",
			"is_domain_name_server": false,
			"resolve": []map[string]interface{}{
				{"type": "A", "record": "localhost", "value": "127.0.0.1", "ttl": 60},
			},
		},
	}

	if m.config.Mode == "interactsh" {
		// 从 payload URL 提取域名
		subdomain := m.interactshURL
		if len(subdomain) > 7 && subdomain[:7] == "http://" {
			subdomain = subdomain[7:]
		} else if len(subdomain) > 8 && subdomain[:8] == "https://" {
			subdomain = subdomain[8:]
		}
		for i := 0; i < len(subdomain); i++ {
			if subdomain[i] == '/' {
				subdomain = subdomain[:i]
				break
			}
		}

		reverse["dns"] = map[string]interface{}{
			"enabled":               false,
			"listen_ip":             "0.0.0.0",
			"domain":                subdomain,
			"is_domain_name_server": false,
			"resolve": []map[string]interface{}{
				{"type": "A", "record": "localhost", "value": "127.0.0.1", "ttl": 60},
			},
		}
		reverse["client"] = map[string]interface{}{
			"remote_server":      true,
			"http_base_url":      fmt.Sprintf("http://%s", subdomain),
			"dns_server_ip":      "",
			"reverse_server_url": fmt.Sprintf("http://%s", m.adapterListen()),
			"reverse_api":        fmt.Sprintf("http://%s/api/v1/reverse/", m.adapterListen()),
		}
	} else {
		// local 模式
		dnsPort := m.config.DNSPort
		if dnsPort == 0 {
			dnsPort = 53
		}
		httpPort := m.config.HTTPPort
		if httpPort == 0 {
			httpPort = 80
		}

		reverse["http"] = map[string]interface{}{
			"enabled":     true,
			"listen_ip":   m.config.ListenIP,
			"listen_port": fmt.Sprintf("%d", httpPort),
			"ip_header":   "",
		}
		reverse["dns"] = map[string]interface{}{
			"enabled":               true,
			"listen_ip":             m.config.ListenIP,
			"domain":                m.config.Domain,
			"is_domain_name_server": m.config.DNSIsNS,
			"resolve": []map[string]interface{}{
				{"type": "A", "record": "localhost", "value": "127.0.0.1", "ttl": 60},
			},
		}
		reverse["client"] = map[string]interface{}{
			"remote_server": false,
			"http_base_url": fmt.Sprintf("http://%s:%d", m.config.ListenIP, httpPort),
			"dns_server_ip": m.config.ListenIP,
		}
	}

	return reverse
}

func (m *Manager) adapterListen() string {
	if m.config.AdapterListen != "" {
		return m.config.AdapterListen
	}
	return "127.0.0.1:9900"
}

func (m *Manager) loadRecords() {
	if m.recordsFile == "" {
		return
	}
	data, err := os.ReadFile(m.recordsFile)
	if err != nil {
		if !os.IsNotExist(err) {
			m.logger.Warn("read OOB interaction store failed", "error", err, "path", m.recordsFile)
		}
		return
	}

	var records map[string][]OOBRecord
	if err := json.Unmarshal(data, &records); err != nil {
		m.logger.Warn("parse OOB interaction store failed", "error", err, "path", m.recordsFile)
		return
	}
	if records == nil {
		return
	}

	m.recordsMu.Lock()
	m.records = records
	m.recordsMu.Unlock()

	total := 0
	for _, recs := range records {
		total += len(recs)
	}
	m.logger.Info("OOB interaction store loaded", "path", m.recordsFile, "records", total)
}

func (m *Manager) saveRecordsLocked() {
	if m.recordsFile == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(m.recordsFile), 0755); err != nil {
		m.logger.Warn("create OOB interaction store dir failed", "error", err, "path", m.recordsFile)
		return
	}
	data, err := json.MarshalIndent(m.records, "", "  ")
	if err != nil {
		m.logger.Warn("marshal OOB interaction store failed", "error", err)
		return
	}
	if err := os.WriteFile(m.recordsFile, data, 0644); err != nil {
		m.logger.Warn("write OOB interaction store failed", "error", err, "path", m.recordsFile)
	}
}

// Status 获取反连平台状态
func (m *Manager) Status() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.recordsMu.Lock()
	totalRecords := 0
	for _, recs := range m.records {
		totalRecords += len(recs)
	}
	m.recordsMu.Unlock()

	return map[string]interface{}{
		"enabled":      m.config.Enabled,
		"mode":         m.config.Mode,
		"domain":       m.config.Domain,
		"payload_url":  m.interactshURL,
		"running":      m.running,
		"records":      totalRecords,
		"records_file": m.recordsFile,
	}
}

func (m *Manager) InteractionChan() <-chan model.OOBInteraction {
	return m.interactionChan
}

// GetInteractions 获取OOB交互记录
func (m *Manager) GetInteractions() []model.OOBInteraction {
	m.recordsMu.Lock()
	defer m.recordsMu.Unlock()

	var result []model.OOBInteraction
	for _, records := range m.records {
		for _, r := range records {
			result = append(result, model.OOBInteraction{
				Protocol:      r.Protocol,
				FullID:        r.FullID,
				RawRequest:    r.RawRequest,
				RawResponse:   r.RawResponse,
				RemoteAddress: r.RemoteAddress,
				Timestamp:     time.Unix(r.Timestamp, 0),
			})
		}
	}
	return result
}

// XRay Reverse配置结构体
type XRayReverseConfig struct {
	Client     XRayReverseClient `yaml:"client"`
	DBFilePath string            `yaml:"db_file_path"`
	DNS        XRayReverseDNS    `yaml:"dns"`
	HTTP       XRayReverseHTTP   `yaml:"http"`
	RMI        XRayReverseRMI    `yaml:"rmi"`
	Token      string            `yaml:"token"`
}

type XRayReverseClient struct {
	DNSServerIP      string `yaml:"dns_server_ip"`
	HTTPBaseURL      string `yaml:"http_base_url"`
	RemoteServer     bool   `yaml:"remote_server"`
	ReverseAPI       string `yaml:"reverse_api"`
	ReverseServerURL string `yaml:"reverse_server_url"`
	RMIServerAddr    string `yaml:"rmi_server_addr"`
}

type XRayReverseDNS struct {
	Domain             string           `yaml:"domain"`
	Enabled            bool             `yaml:"enabled"`
	IsDomainNameServer bool             `yaml:"is_domain_name_server"`
	ListenIP           string           `yaml:"listen_ip"`
	Resolve            []XRayDNSResolve `yaml:"resolve"`
}

type XRayDNSResolve struct {
	Record string `yaml:"record"`
	TTL    int    `yaml:"ttl"`
	Type   string `yaml:"type"`
	Value  string `yaml:"value"`
}

type XRayReverseHTTP struct {
	Enabled    bool   `yaml:"enabled"`
	IPHeader   string `yaml:"ip_header"`
	ListenIP   string `yaml:"listen_ip"`
	ListenPort string `yaml:"listen_port"`
}

type XRayReverseRMI struct {
	Enabled    bool   `yaml:"enabled"`
	ListenIP   string `yaml:"listen_ip"`
	ListenPort string `yaml:"listen_port"`
}
