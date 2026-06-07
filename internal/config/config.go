package config

import (
	"fmt"
	"net/url"
	"os"

	"gopkg.in/yaml.v3"
)

// AgentConfig Agent配置
type AgentConfig struct {
	Server ServerConfig `yaml:"server"`
	Proxy  ProxyConfig  `yaml:"proxy"`
	Log    LogConfig    `yaml:"log"`
}

// ServerConfig 远端Server配置
type ServerConfig struct {
	Address string `yaml:"address"`
	Token   string `yaml:"token"`
}

// ProxyConfig 代理配置
type ProxyConfig struct {
	Listen  string `yaml:"listen"`   // :9090
	CertDir string `yaml:"cert_dir"` // 证书存储目录，默认 ./certs
}

// LogConfig 日志配置
type LogConfig struct {
	Level  string `yaml:"level"`  // debug, info, warn, error
	Output string `yaml:"output"` // stdout, file
	File   string `yaml:"file"`
}

// ServerConfigFile Server端配置
type ServerConfigFile struct {
	Server  ServerListenConfig  `yaml:"server"`
	XRay    XRayConfig          `yaml:"xray"`
	Reverse ReverseConfig       `yaml:"reverse"`
	Webhook WebhookGlobalConfig `yaml:"webhook"`
	DB      DBConfig            `yaml:"db"`
	Log     LogConfig           `yaml:"log"`
}

// ServerListenConfig Server监听配置
type ServerListenConfig struct {
	HTTP  string `yaml:"http"` // :8090
	API   string `yaml:"api"`  // :8081
	Token string `yaml:"token"`
}

// XRayConfig XRay配置
type XRayConfig struct {
	Binary     string `yaml:"binary"`
	Config     string `yaml:"config"`
	DataDir    string `yaml:"data_dir"`
	Listen     string `yaml:"listen"`
	Level      string `yaml:"level"`
	Plugins    string `yaml:"plugins"`
	WebhookURL string `yaml:"webhook_url"`
}

// ReverseConfig XRay反连平台配置
type ReverseConfig struct {
	Enabled          bool   `yaml:"enabled"`
	Mode             string `yaml:"mode"`
	Token            string `yaml:"token"`
	Domain           string `yaml:"domain"`
	ListenIP         string `yaml:"listen_ip"`
	DNSPort          int    `yaml:"dns_port"`
	HTTPPort         int    `yaml:"http_port"`
	DNSIsNS          bool   `yaml:"dns_is_ns"`
	InteractshServer string `yaml:"interactsh_server"`
	InteractshToken  string `yaml:"interactsh_token"`
	AdapterListen    string `yaml:"adapter_listen"`
}

// WebhookGlobalConfig Webhook全局配置
type WebhookGlobalConfig struct {
	Enabled     bool   `yaml:"enabled"`
	MinSeverity string `yaml:"min_severity"`
}

// DBConfig 数据库配置
type DBConfig struct {
	Type string `yaml:"type"`
	DSN  string `yaml:"dsn"`
}

// ParseAgentURI 从 xray:// URI 解析Agent配置
// 格式: xray://token@host:port?listen=:9090
func ParseAgentURI(uri string) (*AgentConfig, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("invalid URI: %w", err)
	}

	if u.Scheme != "xray" {
		return nil, fmt.Errorf("invalid scheme %q, expected 'xray'", u.Scheme)
	}

	token := u.User.Username()
	if token == "" {
		return nil, fmt.Errorf("missing token in URI, format: xray://token@host:port")
	}

	host := u.Host
	if host == "" {
		return nil, fmt.Errorf("missing host in URI")
	}

	// 构建server地址
	address := fmt.Sprintf("http://%s", host)

	// 解析query参数
	q := u.Query()
	listen := q.Get("listen")
	if listen == "" {
		listen = ":9090"
	}

	return &AgentConfig{
		Server: ServerConfig{
			Address: address,
			Token:   token,
		},
		Proxy: ProxyConfig{
			Listen:  listen,
			CertDir: "./certs",
		},
		Log: LogConfig{
			Level:  "info",
			Output: "stdout",
		},
	}, nil
}

// GenerateAgentURI 根据Server配置生成Agent连接URI
func GenerateAgentURI(cfg *ServerConfigFile) string {
	apiAddr := cfg.Server.API
	// 去掉前导冒号格式化为 host:port
	host := apiAddr
	if host[0] == ':' {
		host = "localhost" + host
	}
	return fmt.Sprintf("xray://%s@%s", cfg.Server.Token, host)
}

// LoadAgentConfig 加载Agent配置
func LoadAgentConfig(path string) (*AgentConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &AgentConfig{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// SaveAgentConfig 保存Agent配置
func SaveAgentConfig(path string, cfg *AgentConfig) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// LoadServerConfig 加载Server配置
func LoadServerConfig(path string) (*ServerConfigFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &ServerConfigFile{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
