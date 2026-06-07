package config

import (
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
	Address string `yaml:"address"` // http://server:8080
	Token   string `yaml:"token"`
}

// ProxyConfig 代理配置
type ProxyConfig struct {
	Listen  string `yaml:"listen"`   // :9090
	Target  string `yaml:"target"`   // http://localhost:8080 - 转发目标
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
	HTTP  string `yaml:"http"` // :8080
	API   string `yaml:"api"`  // :8081
	Token string `yaml:"token"`
}

// XRayConfig XRay配置
type XRayConfig struct {
	Binary     string `yaml:"binary"`      // xray binary path
	Config     string `yaml:"config"`      // xray配置文件路径
	DataDir    string `yaml:"data_dir"`    // 数据目录
	Listen     string `yaml:"listen"`      // 被动扫描监听地址，默认 127.0.0.1:7777
	Level      string `yaml:"level"`       // 漏洞等级过滤: low, medium, high, critical
	Plugins    string `yaml:"plugins"`     // 指定插件，逗号分隔
	WebhookURL string `yaml:"webhook_url"` // xray webhook-output目标URL，留空则自动生成
}

// ReverseConfig XRay反连平台配置
type ReverseConfig struct {
	Enabled          bool   `yaml:"enabled"`
	Mode             string `yaml:"mode"` // local 或 interactsh
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
	MinSeverity string `yaml:"min_severity"` // high, medium, low
}

// DBConfig 数据库配置
type DBConfig struct {
	Type string `yaml:"type"` // sqlite, mysql
	DSN  string `yaml:"dsn"`  // database source name
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
