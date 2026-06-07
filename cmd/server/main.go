package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/xray-distribute/internal/api"
	"github.com/xray-distribute/internal/cert"
	"github.com/xray-distribute/internal/config"
	"github.com/xray-distribute/internal/mirror"
	"github.com/xray-distribute/internal/model"
	"github.com/xray-distribute/internal/recordproxy"
	"github.com/xray-distribute/internal/reverse"
	"github.com/xray-distribute/internal/store"
	"github.com/xray-distribute/internal/webhook"
	"github.com/xray-distribute/internal/xray"
	"github.com/xray-distribute/web"
)

func main() {
	configFile := flag.String("config", "config.yaml", "config file path")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// 加载配置
	cfg, err := config.LoadServerConfig(*configFile)
	if err != nil {
		logger.Error("load config failed", "error", err)
		os.Exit(1)
	}

	// 确保数据目录存在
	os.MkdirAll(cfg.XRay.DataDir, 0755)

	// 初始化证书管理器
	certDir := filepath.Join(cfg.XRay.DataDir, "certs")
	certMgr, err := cert.NewCertManager(certDir, logger)
	if err != nil {
		logger.Error("init cert manager failed", "error", err)
		os.Exit(1)
	}
	logger.Info("CA certificate ready", "cert_dir", certDir)

	// 初始化存储
	st := store.New(cfg.XRay.DataDir, logger)

	recordingProxyAddr := "127.0.0.1:9910"
	recordingProxy := recordproxy.New(recordingProxyAddr, st.TrafficDB(), logger)
	if err := recordingProxy.Start(); err != nil {
		logger.Warn("recording proxy start failed", "error", err)
	}

	// 初始化XRay管理器
	xrayListen := cfg.XRay.Listen
	if xrayListen == "" {
		xrayListen = "127.0.0.1:7777"
	}
	xrayWebhookURL := cfg.XRay.WebhookURL
	if xrayWebhookURL == "" {
		xrayWebhookURL = fmt.Sprintf("http://127.0.0.1%s/api/v1/xray/webhook", cfg.Server.API)
	}
	xrayMgr := xray.NewManager(cfg.XRay.Binary, cfg.XRay.Config, cfg.XRay.DataDir, xrayListen, xrayWebhookURL, cfg.XRay.Level, cfg.XRay.Plugins, logger)

	// 初始化反连平台（如果启用）
	var reverseMgr *reverse.Manager
	if cfg.Reverse.Enabled {
		reverseCfg := reverse.ReverseConfig{
			Enabled:          cfg.Reverse.Enabled,
			Mode:             cfg.Reverse.Mode,
			Token:            cfg.Reverse.Token,
			Domain:           cfg.Reverse.Domain,
			ListenIP:         cfg.Reverse.ListenIP,
			DNSPort:          cfg.Reverse.DNSPort,
			HTTPPort:         cfg.Reverse.HTTPPort,
			DNSIsNS:          cfg.Reverse.DNSIsNS,
			InteractshServer: cfg.Reverse.InteractshServer,
			InteractshToken:  cfg.Reverse.InteractshToken,
			AdapterListen:    cfg.Reverse.AdapterListen,
			RecordingProxy:   fmt.Sprintf("http://%s", recordingProxyAddr),
		}
		reverseMgr = reverse.NewManager(cfg.XRay.Binary, cfg.XRay.DataDir, reverseCfg, logger)
		if err := reverseMgr.Start(); err != nil {
			logger.Warn("reverse platform start failed", "error", err)
		} else {
			generatedConfig, err := reverseMgr.GenerateXRayConfig(cfg.XRay.Config)
			if err != nil {
				logger.Warn("generate xray config with reverse failed", "error", err)
			} else if generatedConfig != cfg.XRay.Config {
				xrayMgr.SetGeneratedConfig(generatedConfig)
				logger.Info("xray will use reverse-generated config", "config", generatedConfig)
			}
		}
	}

	// 初始化Webhook通知器
	notifier := webhook.NewNotifier(logger)

	// 加载已保存的Webhook配置
	for _, wh := range st.GetWebhooks() {
		notifier.AddConfig(wh)
	}

	// 初始化流量接收器（默认500 QPS限速）
	recv := mirror.NewReceiver(logger, 500)
	recv.SetOnRequest(func(req *model.MirrorRequest) {
		if err := xrayMgr.SendToXRay(req); err != nil {
			logger.Debug("send to xray failed", "error", err)
		}
	})

	// 监听XRay漏洞输出
	go func() {
		for vuln := range xrayMgr.VulnChan() {
			st.AddVuln(vuln)
			if cfg.Webhook.Enabled {
				notifier.Notify(vuln)
			}
			logger.Info("vulnerability found",
				"severity", vuln.Severity,
				"title", vuln.Title,
				"url", vuln.URL)
		}
	}()

	if reverseMgr != nil {
		go func() {
			for interaction := range reverseMgr.InteractionChan() {
				match, err := st.RecordOOBInteraction(interaction)
				if err != nil {
					logger.Warn("record OOB interaction failed", "error", err, "full_id", interaction.FullID)
				}
				request := interaction.RawRequest
				description := fmt.Sprintf("Remote address: %s", interaction.RemoteAddress)
				detail := map[string]interface{}{
					"oob_protocol": interaction.Protocol,
					"oob_full_id":  interaction.FullID,
					"oob_request":  interaction.RawRequest,
					"oob_response": interaction.RawResponse,
				}
				if match != nil {
					request = match.Raw
					description = fmt.Sprintf("Remote address: %s; matched %s request #%d: %s", interaction.RemoteAddress, match.Source, match.ID, match.URL)
					detail["matched_source"] = match.Source
					detail["matched_id"] = match.ID
					detail["matched_method"] = match.Method
					detail["matched_url"] = match.URL
					detail["matched_raw"] = match.Raw
					detail["matched_created_at"] = match.CreatedAt
				}
				detailJSON, _ := json.Marshal(detail)
				vuln := &model.Vulnerability{
					ID:          fmt.Sprintf("oob-%s-%s-%d", interaction.Protocol, interaction.FullID, interaction.Timestamp.UnixNano()),
					Plugin:      "interactsh",
					URL:         interaction.FullID,
					VulnClass:   "oob-interaction",
					Severity:    "medium",
					Title:       fmt.Sprintf("OOB interaction received (%s)", interaction.Protocol),
					Description: description,
					Request:     request,
					Response:    interaction.RawResponse,
					Detail:      string(detailJSON),
					CreatedAt:   interaction.Timestamp,
				}
				st.AddVuln(vuln)
				if cfg.Webhook.Enabled {
					notifier.Notify(vuln)
				}
				logger.Info("OOB interaction reported",
					"protocol", interaction.Protocol,
					"full_id", interaction.FullID,
					"remote", interaction.RemoteAddress)
			}
		}()
	}

	// 初始化API服务器
	apiServer := api.New(st, xrayMgr, recv, notifier, certMgr, reverseMgr, cfg.Server.Token, logger)

	// 启动API服务
	go func() {
		handler := apiServer.Handler()
		logger.Info("api server starting", "addr", cfg.Server.API)
		if err := httpListenAndServe(cfg.Server.API, handler); err != nil {
			logger.Error("api server error", "error", err)
		}
	}()

	// Start embedded web panel.
	go func() {
		logger.Info("web panel starting", "addr", cfg.Server.HTTP)
		if err := httpListenAndServe(cfg.Server.HTTP, web.PanelHandler(apiServer.Handler())); err != nil {
			logger.Error("web panel error", "error", err)
		}
	}()

	// 输出Agent连接URI
	agentURI := config.GenerateAgentURI(cfg)
	publicIP := config.GetPublicIP()

	displayHost := "localhost"
	if publicIP != "" {
		displayHost = publicIP
	}

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("  XRay-Distribute Server Started")
	fmt.Println("========================================")
	fmt.Printf("  Web Panel:  http://%s%s\n", displayHost, cfg.Server.HTTP)
	fmt.Printf("  API:        http://%s%s\n", displayHost, cfg.Server.API)
	fmt.Println()
	fmt.Println("  Agent连接命令（复制给Agent端执行）:")
	fmt.Printf("  agent %s\n", agentURI)
	fmt.Println("========================================")
	fmt.Println()

	logger.Info("xray-distribute server started",
		"http", cfg.Server.HTTP,
		"api", cfg.Server.API)

	// 等待退出信号
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	xrayMgr.Stop()
	if reverseMgr != nil {
		reverseMgr.Stop()
	}
	notifier.Stop()
	_ = ctx

	logger.Info("server stopped")
}

func httpListenAndServe(addr string, handler http.Handler) error {
	srv := &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	return srv.ListenAndServe()
}
