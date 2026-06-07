package store

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/xray-distribute/internal/model"
	"github.com/xray-distribute/internal/trafficdb"
)

// Store 数据存储（基于文件的简单存储，后续可替换为SQLite）
type Store struct {
	dataDir   string
	logger    *slog.Logger
	trafficDB *trafficdb.DB
	mu        sync.RWMutex

	agents   map[string]*model.Agent
	vulns    []*model.Vulnerability
	traffic  []*model.MirrorRequest
	webhooks map[string]*model.WebhookConfig
}

// New 创建存储
func New(dataDir string, logger *slog.Logger) *Store {
	tdb, err := trafficdb.Open(filepath.Join(dataDir, "traffic.db"))
	if err != nil {
		logger.Error("open traffic db failed", "error", err)
	}

	s := &Store{
		dataDir:   dataDir,
		logger:    logger,
		trafficDB: tdb,
		agents:    make(map[string]*model.Agent),
		vulns:     make([]*model.Vulnerability, 0),
		traffic:   make([]*model.MirrorRequest, 0),
		webhooks:  make(map[string]*model.WebhookConfig),
	}

	// 加载持久化数据
	s.load()

	// 启动traffic db每日滚动
	if tdb != nil {
		tdb.StartRotationTicker(logger)
	}

	return s
}

// --- Agent ---

// RegisterAgent 注册Agent
func (s *Store) RegisterAgent(agent *model.Agent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	agent.LastHeartbeat = time.Now()
	agent.Status = "online"
	s.agents[agent.ID] = agent
	s.save()
}

// UpdateHeartbeat 更新Agent心跳
func (s *Store) UpdateHeartbeat(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if agent, ok := s.agents[id]; ok {
		agent.LastHeartbeat = time.Now()
		agent.Status = "online"
	}
}

// GetAgents 获取所有Agent
func (s *Store) GetAgents() []*model.Agent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// 检查离线
	now := time.Now()
	agents := make([]*model.Agent, 0, len(s.agents))
	for _, a := range s.agents {
		if now.Sub(a.LastHeartbeat) > 60*time.Second {
			a.Status = "offline"
		}
		agents = append(agents, a)
	}
	return agents
}

// GetAgent 获取单个Agent
func (s *Store) GetAgent(id string) *model.Agent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.agents[id]
}

// DeleteAgent 删除Agent
func (s *Store) DeleteAgent(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.agents, id)
	s.save()
}

// --- Vulnerability ---

// AddVuln 添加漏洞
func (s *Store) AddVuln(vuln *model.Vulnerability) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vulns = append(s.vulns, vuln)
	s.save()
}

// GetVulns 获取漏洞列表
func (s *Store) GetVulns(severity, keyword string, page, pageSize int) ([]*model.Vulnerability, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	filtered := make([]*model.Vulnerability, 0)
	for _, v := range s.vulns {
		if severity != "" && v.Severity != severity {
			continue
		}
		if keyword != "" {
			if !contains(v.Title, keyword) && !contains(v.URL, keyword) {
				continue
			}
		}
		filtered = append(filtered, v)
	}

	total := len(filtered)
	start := (page - 1) * pageSize
	if start >= total {
		return []*model.Vulnerability{}, total
	}
	end := start + pageSize
	if end > total {
		end = total
	}

	return filtered[start:end], total
}

// GetVuln 获取单个漏洞
func (s *Store) GetVuln(id string) *model.Vulnerability {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, v := range s.vulns {
		if v.ID == id {
			return v
		}
	}
	return nil
}

// GetVulnStats 获取漏洞统计
func (s *Store) GetVulnStats() *model.TrafficStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := &model.TrafficStats{}
	today := time.Now().Truncate(24 * time.Hour)

	for _, v := range s.vulns {
		stats.TotalVulns++
		switch v.Severity {
		case "high":
			stats.HighVulns++
		case "medium":
			stats.MediumVulns++
		case "low":
			stats.LowVulns++
		}
		if v.CreatedAt.After(today) {
			// today vulns
		}
		if stats.LastVulnTime == nil || v.CreatedAt.After(*stats.LastVulnTime) {
			t := v.CreatedAt
			stats.LastVulnTime = &t
		}
	}

	// 统计在线Agent
	for _, a := range s.agents {
		if a.Status == "online" {
			stats.ActiveAgents++
		}
	}

	return stats
}

// --- Traffic ---

func (s *Store) AddTraffic(requests []*model.MirrorRequest) {
	if len(requests) == 0 {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.traffic = append(s.traffic, requests...)
	const maxTrafficRecords = 10000
	if len(s.traffic) > maxTrafficRecords {
		s.traffic = s.traffic[len(s.traffic)-maxTrafficRecords:]
	}
	s.save()

	if s.trafficDB != nil {
		for _, req := range requests {
			if _, err := s.trafficDB.RecordMirror(req); err != nil {
				s.logger.Warn("record mirror traffic failed", "error", err, "url", req.URL)
			}
		}
	}
}

func (s *Store) TrafficDB() *trafficdb.DB {
	return s.trafficDB
}

func (s *Store) RecordOOBInteraction(interaction model.OOBInteraction) (*trafficdb.Match, error) {
	if s.trafficDB == nil {
		return nil, nil
	}
	return s.trafficDB.RecordOOB(interaction)
}

// --- Webhook ---

// AddWebhook 添加Webhook
func (s *Store) AddWebhook(cfg *model.WebhookConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.webhooks[cfg.ID] = cfg
	s.save()
}

// GetWebhooks 获取所有Webhook
func (s *Store) GetWebhooks() []*model.WebhookConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()

	configs := make([]*model.WebhookConfig, 0, len(s.webhooks))
	for _, cfg := range s.webhooks {
		configs = append(configs, cfg)
	}
	return configs
}

// GetWebhook 获取单个Webhook
func (s *Store) GetWebhook(id string) *model.WebhookConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.webhooks[id]
}

// UpdateWebhook 更新Webhook
func (s *Store) UpdateWebhook(cfg *model.WebhookConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.webhooks[cfg.ID] = cfg
	s.save()
}

// DeleteWebhook 删除Webhook
func (s *Store) DeleteWebhook(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.webhooks, id)
	s.save()
}

// --- Persistence ---

type persistData struct {
	Agents   []*model.Agent         `json:"agents"`
	Vulns    []*model.Vulnerability `json:"vulns"`
	Traffic  []*model.MirrorRequest `json:"traffic"`
	Webhooks []*model.WebhookConfig `json:"webhooks"`
}

func (s *Store) save() {
	data := persistData{
		Agents:   make([]*model.Agent, 0, len(s.agents)),
		Vulns:    s.vulns,
		Traffic:  s.traffic,
		Webhooks: make([]*model.WebhookConfig, 0, len(s.webhooks)),
	}
	for _, a := range s.agents {
		data.Agents = append(data.Agents, a)
	}
	for _, w := range s.webhooks {
		data.Webhooks = append(data.Webhooks, w)
	}

	filePath := filepath.Join(s.dataDir, "store.json")
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		s.logger.Error("marshal store data failed", "error", err)
		return
	}
	if err := os.WriteFile(filePath, b, 0644); err != nil {
		s.logger.Error("write store file failed", "error", err)
	}
}

func (s *Store) load() {
	filePath := filepath.Join(s.dataDir, "store.json")
	b, err := os.ReadFile(filePath)
	if err != nil {
		if !os.IsNotExist(err) {
			s.logger.Error("read store file failed", "error", err)
		}
		return
	}

	var data persistData
	if err := json.Unmarshal(b, &data); err != nil {
		s.logger.Error("unmarshal store data failed", "error", err)
		return
	}

	for _, a := range data.Agents {
		s.agents[a.ID] = a
	}
	s.vulns = data.Vulns
	if s.vulns == nil {
		s.vulns = make([]*model.Vulnerability, 0)
	}
	s.traffic = data.Traffic
	if s.traffic == nil {
		s.traffic = make([]*model.MirrorRequest, 0)
	}
	for _, w := range data.Webhooks {
		s.webhooks[w.ID] = w
	}

	s.logger.Info("store loaded", "agents", len(s.agents), "vulns", len(s.vulns), "traffic", len(s.traffic), "webhooks", len(s.webhooks))
}

// --- Traffic Counter ---

var (
	requestCount int64
	todayCount   int64
	countMu      sync.Mutex
	lastReset    time.Time
)

// IncrRequest 增加请求计数
func IncrRequest() {
	countMu.Lock()
	defer countMu.Unlock()

	now := time.Now()
	if now.Truncate(24*time.Hour) != lastReset.Truncate(24*time.Hour) {
		todayCount = 0
		lastReset = now
	}
	requestCount++
	todayCount++
}

// GetRequestCount 获取请求计数
func GetRequestCount() (total int64, today int64) {
	countMu.Lock()
	defer countMu.Unlock()
	return requestCount, todayCount
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstr(s, substr)))
}

func findSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// GenerateID 生成简单ID
func GenerateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
