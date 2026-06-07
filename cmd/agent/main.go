package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/xray-distribute/internal/cert"
	"github.com/xray-distribute/internal/config"
	"github.com/xray-distribute/internal/mirror"
	"github.com/xray-distribute/internal/proxy"
)

func main() {
	configFile := flag.String("config", "agent.yaml", "config file path")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// 加载配置
	cfg, err := config.LoadAgentConfig(*configFile)
	if err != nil {
		logger.Error("load config failed", "error", err)
		os.Exit(1)
	}

	// 验证与Server的连接
	if !mirror.ValidateToken(cfg.Server.Address, cfg.Server.Token) {
		logger.Error("validate server token failed, check server address and token")
		os.Exit(1)
	}

	logger.Info("server connection validated", "server", cfg.Server.Address)

	// 初始化证书管理器
	certDir := cfg.Proxy.CertDir
	if certDir == "" {
		certDir = "./certs"
	}
	certMgr, err := cert.NewCertManager(certDir, logger)
	if err != nil {
		logger.Error("init cert manager failed", "error", err)
		os.Exit(1)
	}

	logger.Info("CA certificate ready",
		"cert_dir", certDir,
		"ca_cert", certDir+"/ca.crt",
		"hint", "import ca.crt to your device to trust HTTPS proxy")

	// 创建镜像发送器
	sender := mirror.NewSender(cfg.Server.Address, cfg.Server.Token, logger)

	// 创建镜像代理
	p, err := proxy.New(cfg.Proxy.Listen, cfg.Proxy.Target, sender, certMgr, logger)
	if err != nil {
		logger.Error("create proxy failed", "error", err)
		os.Exit(1)
	}

	// 启动代理
	go func() {
		if err := p.Start(); err != nil {
			logger.Error("proxy error", "error", err)
			os.Exit(1)
		}
	}()

	logger.Info("agent started",
		"listen", cfg.Proxy.Listen,
		"target", cfg.Proxy.Target,
		"server", cfg.Server.Address)

	// 等待退出信号
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	p.Stop(ctx)
	sender.Stop()

	logger.Info("agent stopped")
}
