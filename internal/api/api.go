package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/xray-distribute/internal/cert"
	"github.com/xray-distribute/internal/mirror"
	"github.com/xray-distribute/internal/model"
	"github.com/xray-distribute/internal/reverse"
	"github.com/xray-distribute/internal/store"
	"github.com/xray-distribute/internal/webhook"
	"github.com/xray-distribute/internal/xray"
)

// Server API服务器
type Server struct {
	store    *store.Store
	xray     *xray.Manager
	mirror   *mirror.Receiver
	notifier *webhook.Notifier
	certMgr  *cert.CertManager
	reverse  *reverse.Manager
	token    string
	logger   *slog.Logger
}

// New 创建API服务器
func New(s *store.Store, x *xray.Manager, m *mirror.Receiver, n *webhook.Notifier, cm *cert.CertManager, r *reverse.Manager, token string, logger *slog.Logger) *Server {
	return &Server{
		store:    s,
		xray:     x,
		mirror:   m,
		notifier: n,
		certMgr:  cm,
		reverse:  r,
		token:    token,
		logger:   logger,
	}
}

// Handler 返回HTTP Handler
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// 镜像流量接收
	mux.HandleFunc("/api/v1/mirror/batch", s.auth(s.handleMirrorBatch))

	// Agent管理
	mux.HandleFunc("/api/v1/agents", s.auth(s.handleAgents))
	mux.HandleFunc("/api/v1/agents/register", s.auth(s.handleAgentRegister))
	mux.HandleFunc("/api/v1/agents/heartbeat", s.auth(s.handleAgentHeartbeat))

	// XRay管理
	mux.HandleFunc("/api/v1/xray/status", s.auth(s.handleXRayStatus))
	mux.HandleFunc("/api/v1/xray/start", s.auth(s.handleXRayStart))
	mux.HandleFunc("/api/v1/xray/stop", s.auth(s.handleXRayStop))
	mux.HandleFunc("/api/v1/xray/restart", s.auth(s.handleXRayRestart))
	mux.HandleFunc("/api/v1/xray/logs", s.auth(s.handleXRayLogs))

	// XRay Webhook接收（xray --webhook-output 发送到此端点，无需auth因为xray不带token）
	mux.HandleFunc("/api/v1/xray/webhook", s.handleXRayWebhook)

	// 漏洞管理
	mux.HandleFunc("/api/v1/vulns", s.auth(s.handleVulns))
	mux.HandleFunc("/api/v1/vulns/stats", s.auth(s.handleVulnStats))

	// 队列监控与流速控制
	mux.HandleFunc("/api/v1/queue/stats", s.auth(s.handleQueueStats))
	mux.HandleFunc("/api/v1/queue/flow", s.auth(s.handleQueueFlow))

	// Interactsh OOB交互
	mux.HandleFunc("/api/v1/reverse/status", s.auth(s.handleReverseStatus))
	mux.HandleFunc("/api/v1/reverse/interactions", s.auth(s.handleReverseInteractions))

	// Webhook管理
	mux.HandleFunc("/api/v1/webhooks", s.auth(s.handleWebhooks))
	mux.HandleFunc("/api/v1/webhooks/test", s.auth(s.handleWebhookTest))

	// CA证书下载（无需认证，方便手机直接下载）
	mux.HandleFunc("/api/v1/cert/ca.crt", s.handleCACertPEM)
	mux.HandleFunc("/api/v1/cert/ca.der", s.handleCACertDER)

	// 健康检查
	mux.HandleFunc("/api/v1/ping", s.handlePing)

	return mux
}

// auth 认证中间件
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-Token")
		if token == "" {
			token = r.URL.Query().Get("token")
		}
		if token != s.token {
			s.jsonResponse(w, http.StatusUnauthorized, "unauthorized", nil)
			return
		}
		next(w, r)
	}
}

// handleMirrorBatch 接收镜像流量
func (s *Server) handleMirrorBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonResponse(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	var requests []*model.MirrorRequest
	if err := json.NewDecoder(r.Body).Decode(&requests); err != nil {
		s.jsonResponse(w, http.StatusBadRequest, "invalid request body", nil)
		return
	}

	s.mirror.HandleBatch(requests)
	s.store.AddTraffic(requests)

	// 计数
	for range requests {
		store.IncrRequest()
	}

	s.jsonResponse(w, http.StatusOK, "ok", map[string]int{"count": len(requests)})
}

// handleAgentRegister Agent注册
func (s *Server) handleAgentRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonResponse(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	var agent model.Agent
	if err := json.NewDecoder(r.Body).Decode(&agent); err != nil {
		s.jsonResponse(w, http.StatusBadRequest, "invalid request body", nil)
		return
	}

	if agent.ID == "" {
		agent.ID = store.GenerateID()
	}
	agent.CreatedAt = time.Now()
	agent.LastHeartbeat = time.Now()
	agent.Status = "online"

	s.store.RegisterAgent(&agent)
	s.jsonResponse(w, http.StatusOK, "ok", agent)
}

// handleAgentHeartbeat Agent心跳
func (s *Server) handleAgentHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonResponse(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonResponse(w, http.StatusBadRequest, "invalid request body", nil)
		return
	}

	s.store.UpdateHeartbeat(req.ID)
	s.jsonResponse(w, http.StatusOK, "ok", nil)
}

// handleAgents 获取Agent列表
func (s *Server) handleAgents(w http.ResponseWriter, r *http.Request) {
	agents := s.store.GetAgents()
	s.jsonResponse(w, http.StatusOK, "ok", agents)
}

// handleXRayStatus XRay状态
func (s *Server) handleXRayStatus(w http.ResponseWriter, r *http.Request) {
	status := s.xray.Status()
	s.jsonResponse(w, http.StatusOK, "ok", status)
}

// handleXRayStart 启动XRay
func (s *Server) handleXRayStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonResponse(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	if err := s.xray.Start("default"); err != nil {
		s.jsonResponse(w, http.StatusInternalServerError, err.Error(), nil)
		return
	}
	s.jsonResponse(w, http.StatusOK, "ok", nil)
}

// handleXRayStop 停止XRay
func (s *Server) handleXRayStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonResponse(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	if err := s.xray.Stop(); err != nil {
		s.jsonResponse(w, http.StatusInternalServerError, err.Error(), nil)
		return
	}
	s.jsonResponse(w, http.StatusOK, "ok", nil)
}

// handleXRayRestart 重启XRay
func (s *Server) handleXRayRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonResponse(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	if err := s.xray.Restart(); err != nil {
		s.jsonResponse(w, http.StatusInternalServerError, err.Error(), nil)
		return
	}
	s.jsonResponse(w, http.StatusOK, "ok", nil)
}

// handleXRayLogs returns recent xray process logs.
func (s *Server) handleXRayLogs(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 200
	}
	s.jsonResponse(w, http.StatusOK, "ok", s.xray.Logs(limit))
}

// handleXRayWebhook 接收XRay通过--webhook-output发送的漏洞数据
// XRay会POST JSON到此端点，无需认证
func (s *Server) handleXRayWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.logger.Error("read xray webhook body failed", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	s.xray.HandleWebhook(json.RawMessage(body))
	w.WriteHeader(http.StatusOK)
}

// handleVulns 漏洞列表
func (s *Server) handleVulns(w http.ResponseWriter, r *http.Request) {
	severity := r.URL.Query().Get("severity")
	keyword := r.URL.Query().Get("keyword")
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))

	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}

	vulns, total := s.store.GetVulns(severity, keyword, page, pageSize)
	s.jsonResponse(w, http.StatusOK, "ok", map[string]interface{}{
		"list":      vulns,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

// handleVulnStats 漏洞统计
func (s *Server) handleVulnStats(w http.ResponseWriter, r *http.Request) {
	stats := s.store.GetVulnStats()
	total, today := store.GetRequestCount()
	stats.TotalRequests = total
	stats.TodayRequests = today
	s.jsonResponse(w, http.StatusOK, "ok", stats)
}

// handleWebhooks Webhook列表
func (s *Server) handleWebhooks(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		configs := s.store.GetWebhooks()
		s.jsonResponse(w, http.StatusOK, "ok", configs)
	case http.MethodPost:
		var cfg model.WebhookConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			s.jsonResponse(w, http.StatusBadRequest, "invalid request body", nil)
			return
		}
		if cfg.ID == "" {
			cfg.ID = store.GenerateID()
		}
		s.store.AddWebhook(&cfg)
		s.notifier.AddConfig(&cfg)
		s.jsonResponse(w, http.StatusOK, "ok", cfg)
	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		s.store.DeleteWebhook(id)
		s.notifier.RemoveConfig(id)
		s.jsonResponse(w, http.StatusOK, "ok", nil)
	default:
		s.jsonResponse(w, http.StatusMethodNotAllowed, "method not allowed", nil)
	}
}

// handleWebhookTest 测试Webhook
func (s *Server) handleWebhookTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonResponse(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonResponse(w, http.StatusBadRequest, "invalid request body", nil)
		return
	}

	testVuln := &model.Vulnerability{
		ID:          "test-001",
		Plugin:      "test",
		URL:         "https://example.com/test?q=1",
		VulnClass:   "sql-injection",
		Severity:    "high",
		Title:       "SQL注入漏洞（测试）",
		Description: "这是一条测试Webhook通知",
		CreatedAt:   time.Now(),
	}

	s.notifier.Notify(testVuln)
	s.jsonResponse(w, http.StatusOK, "test notification sent", nil)
}

// handlePing 健康检查
func (s *Server) handlePing(w http.ResponseWriter, r *http.Request) {
	s.jsonResponse(w, http.StatusOK, "pong", nil)
}

// handleCACertPEM 下载CA证书（PEM格式，.crt）
func (s *Server) handleCACertPEM(w http.ResponseWriter, r *http.Request) {
	if s.certMgr == nil {
		http.Error(w, "CA certificate not available", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", "attachment; filename=xray-distribute-ca.crt")
	w.Write(s.certMgr.GetCACertPEM())
}

// handleCACertDER 下载CA证书（DER格式，手机导入用）
func (s *Server) handleCACertDER(w http.ResponseWriter, r *http.Request) {
	if s.certMgr == nil {
		http.Error(w, "CA certificate not available", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", "attachment; filename=xray-distribute-ca.cer")
	w.Write(s.certMgr.GetCACertDER())
}

// handleQueueStats 队列状态监控
func (s *Server) handleQueueStats(w http.ResponseWriter, r *http.Request) {
	xrayPipeStats := s.mirror.Stats()
	flowStats := s.mirror.FlowStats()

	s.jsonResponse(w, http.StatusOK, "ok", map[string]interface{}{
		"xray_pipe": xrayPipeStats,
		"flow_ctrl": flowStats,
	})
}

// handleQueueFlow 流速控制（动态调整QPS）
func (s *Server) handleQueueFlow(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// 获取当前流速配置
		s.jsonResponse(w, http.StatusOK, "ok", s.mirror.FlowStats())
		return
	}

	if r.Method == http.MethodPost {
		var req struct {
			MaxQPS int `json:"max_qps"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.jsonResponse(w, http.StatusBadRequest, "invalid request", nil)
			return
		}
		if req.MaxQPS > 0 {
			s.mirror.SetMaxQPS(req.MaxQPS)
		}
		s.jsonResponse(w, http.StatusOK, "ok", s.mirror.FlowStats())
		return
	}

	s.jsonResponse(w, http.StatusMethodNotAllowed, "method not allowed", nil)
}

// handleReverseStatus 反连平台状态
func (s *Server) handleReverseStatus(w http.ResponseWriter, r *http.Request) {
	if s.reverse == nil {
		s.jsonResponse(w, http.StatusOK, "ok", map[string]interface{}{
			"enabled": false,
		})
		return
	}
	s.jsonResponse(w, http.StatusOK, "ok", s.reverse.Status())
}

// handleReverseInteractions OOB交互列表
func (s *Server) handleReverseInteractions(w http.ResponseWriter, r *http.Request) {
	if s.reverse == nil {
		s.jsonResponse(w, http.StatusOK, "ok", []model.OOBInteraction{})
		return
	}
	s.jsonResponse(w, http.StatusOK, "ok", s.reverse.GetInteractions())
}

// jsonResponse 统一JSON响应
func (s *Server) jsonResponse(w http.ResponseWriter, code int, message string, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(model.APIResponse{
		Code:    code,
		Message: message,
		Data:    data,
	})
}
