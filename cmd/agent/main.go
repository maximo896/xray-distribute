package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/xray-distribute/internal/cert"
	"github.com/xray-distribute/internal/config"
	"github.com/xray-distribute/internal/mirror"
	"github.com/xray-distribute/internal/proxy"
)

const defaultConfigFile = "agent.yaml"

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// 解析参数：支持 agent xray://token@host:port 格式
	var cfg *config.AgentConfig

	args := os.Args[1:]
	if len(args) > 0 && strings.HasPrefix(args[0], "xray://") {
		// 从URI解析配置
		var err error
		cfg, err = config.ParseAgentURI(args[0])
		if err != nil {
			logger.Error("parse URI failed", "error", err)
			os.Exit(1)
		}
		// 保存配置到文件，下次不用再传URI
		if err := config.SaveAgentConfig(defaultConfigFile, cfg); err != nil {
			logger.Warn("save config failed", "error", err)
		} else {
			logger.Info("config saved", "file", defaultConfigFile)
		}
	} else {
		// 从配置文件加载
		configFile := defaultConfigFile
		if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
			configFile = args[0]
		}
		var err error
		cfg, err = config.LoadAgentConfig(configFile)
		if err != nil {
			fmt.Println("Usage:")
			fmt.Println("  agent xray://token@host:port     # 首次使用，从Server输出的URI启动")
			fmt.Println("  agent                            # 使用已保存的配置启动")
			fmt.Println()
			fmt.Println("Example:")
			fmt.Println("  agent xray://my-secret@192.168.1.100:8081")
			logger.Error("no config found, please run with xray:// URI first", "error", err)
			os.Exit(1)
		}
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
	p, err := proxy.New(cfg.Proxy.Listen, sender, certMgr, logger)
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
