package model

import "time"

// Agent 注册到Server的节点信息
type Agent struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	IP          string    `json:"ip"`
	Status      string    `json:"status"` // online, offline
	LastHeartbeat time.Time `json:"last_heartbeat"`
	CreatedAt   time.Time `json:"created_at"`
}

// XRayInstance XRay扫描实例
type XRayInstance struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Status    string    `json:"status"` // running, stopped, error
	Pid       int       `json:"pid,omitempty"`
	Config    string    `json:"config"`
	Plugin    string    `json:"plugin"` // passive, active, etc.
	CreatedAt time.Time `json:"created_at"`
	StartedAt *time.Time `json:"started_at,omitempty"`
}

// Vulnerability XRay发现的漏洞
type Vulnerability struct {
	ID          string    `json:"id"`
	InstanceID  string    `json:"instance_id"`
	Plugin      string    `json:"plugin"`
	URL         string    `json:"url"`
	VulnClass   string    `json:"vuln_class"` // sql-injection, xss, etc.
	Severity    string    `json:"severity"`   // high, medium, low, info
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Solution    string    `json:"solution"`
	Request     string    `json:"request"`
	Response    string    `json:"response"`
	Detail      string    `json:"detail"`
	CreatedAt   time.Time `json:"created_at"`
	Notified    bool      `json:"notified"`
}

// WebhookConfig Webhook通知配置
type WebhookConfig struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	URL      string `json:"url"`
	Type     string `json:"type"` // dingtalk, wecom, lark, custom
	Enabled  bool   `json:"enabled"`
	Secret   string `json:"secret,omitempty"`
	Template string `json:"template,omitempty"`
}

// MirrorRequest Agent发送镜像流量的请求体
type MirrorRequest struct {
	AgentID   string `json:"agent_id"`
	Method    string `json:"method"`
	URL       string `json:"url"`
	Headers   map[string][]string `json:"headers"`
	Body      []byte `json:"body"`
	Timestamp int64  `json:"timestamp"`
	Protocol  string `json:"protocol"` // http, websocket, h2
}

// TrafficStats 流量统计
type TrafficStats struct {
	TotalRequests   int64     `json:"total_requests"`
	TodayRequests   int64     `json:"today_requests"`
	TotalVulns      int64     `json:"total_vulns"`
	HighVulns       int64     `json:"high_vulns"`
	MediumVulns     int64     `json:"medium_vulns"`
	LowVulns        int64     `json:"low_vulns"`
	ActiveAgents    int64     `json:"active_agents"`
	LastVulnTime    *time.Time `json:"last_vuln_time,omitempty"`
}

// APIResponse 统一API响应
type APIResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// OOBInteraction OOB带外交互记录（interactsh）
type OOBInteraction struct {
	Protocol      string    `json:"protocol"`       // dns, http, smtp, ldap
	FullID        string    `json:"full_id"`        // 完整交互ID
	RawRequest    string    `json:"raw_request"`    // 原始请求
	RawResponse   string    `json:"raw_response"`   // 原始响应
	RemoteAddress string    `json:"remote_address"` // 远端地址
	Timestamp     time.Time `json:"timestamp"`
}
