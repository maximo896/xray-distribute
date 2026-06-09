package updater

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/minio/selfupdate"
)

// Version 当前版本，通过 -ldflags 在构建时注入，默认 "dev"
var Version = "dev"

// GitHub 仓库信息
const (
	RepoOwner = "maximo896"
	RepoName  = "xray-distribute"
)

// RestartFunc 重启函数，可被覆盖以便测试
var RestartFunc = defaultRestart

// GitHubRelease 表示 GitHub Release API 返回的发布信息
type GitHubRelease struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
	Assets  []struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	} `json:"assets"`
}

// Component 表示更新组件类型
type Component string

const (
	ComponentServer Component = "server"
	ComponentAgent  Component = "agent"
)

// CheckForUpdate 检查 GitHub 上是否有新版本
// 返回最新发布信息和是否有更新
func CheckForUpdate() (*GitHubRelease, bool, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", RepoOwner, RepoName)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, false, fmt.Errorf("请求 GitHub API 失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, false, fmt.Errorf("GitHub API 返回状态码 %d: %s", resp.StatusCode, string(body))
	}

	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, false, fmt.Errorf("解析 GitHub Release 失败: %w", err)
	}

	// 比较版本号
	currentVer, err := semver.NewVersion(strings.TrimPrefix(Version, "v"))
	if err != nil {
		// 当前版本无法解析（如 "dev"），认为有更新
		return &release, true, nil
	}

	latestVer, err := semver.NewVersion(strings.TrimPrefix(release.TagName, "v"))
	if err != nil {
		return nil, false, fmt.Errorf("解析最新版本号失败: %w", err)
	}

	hasUpdate := latestVer.GreaterThan(currentVer)
	return &release, hasUpdate, nil
}

// PerformUpdate 执行自更新
// component 指定更新 server 还是 agent
func PerformUpdate(release *GitHubRelease, component Component, logger *slog.Logger) error {
	// 根据组件类型确定下载的 zip 文件名
	var zipFileName string
	switch component {
	case ComponentServer:
		zipFileName = "xray-distribute-server.zip"
	case ComponentAgent:
		zipFileName = "xray-distribute-local.zip"
	default:
		return fmt.Errorf("未知的组件类型: %s", component)
	}

	// 构建下载 URL
	downloadURL := fmt.Sprintf("https://github.com/%s/%s/releases/download/%s/%s",
		RepoOwner, RepoName, release.TagName, zipFileName)

	logger.Info("开始下载更新", "url", downloadURL, "version", release.TagName)

	// 下载 zip 文件
	zipData, err := downloadFile(downloadURL)
	if err != nil {
		return fmt.Errorf("下载更新包失败: %w", err)
	}

	logger.Info("更新包下载完成", "size", len(zipData))

	// 从 zip 中提取目标二进制
	binaryName := getBinaryName(component)
	binaryData, err := extractBinaryFromZip(zipData, binaryName)
	if err != nil {
		return fmt.Errorf("从更新包提取二进制失败: %w", err)
	}

	logger.Info("提取二进制完成", "name", binaryName, "size", len(binaryData))

	// 使用 minio/selfupdate 应用更新
	if err := selfupdate.Apply(bytes.NewReader(binaryData), selfupdate.Options{}); err != nil {
		// 回滚更新
		if rerr := selfupdate.RollbackError(err); rerr != nil {
			logger.Error("更新回滚失败", "error", rerr)
		}
		return fmt.Errorf("应用更新失败: %w", err)
	}

	logger.Info("更新应用成功，准备重启", "new_version", release.TagName)

	// 重启进程
	RestartFunc()

	return nil
}

// getBinaryName 根据组件类型和当前操作系统返回二进制文件名
func getBinaryName(component Component) string {
	switch component {
	case ComponentServer:
		// 服务器端只运行在 Linux 上
		return "xray-distribute"
	case ComponentAgent:
		// Agent 根据操作系统选择
		if runtime.GOOS == "windows" {
			return "agent.exe"
		}
		return "agent"
	default:
		return ""
	}
}

// downloadFile 下载文件并返回内容
func downloadFile(url string) ([]byte, error) {
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("下载失败，状态码: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// extractBinaryFromZip 从 zip 数据中提取指定名称的文件
func extractBinaryFromZip(zipData []byte, filename string) ([]byte, error) {
	reader, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return nil, fmt.Errorf("打开 zip 失败: %w", err)
	}

	for _, file := range reader.File {
		// zip 中的路径可能包含目录前缀，只比较文件名
		if file.Name == filename || stripPath(file.Name) == filename {
			rc, err := file.Open()
			if err != nil {
				return nil, fmt.Errorf("打开 zip 内文件 %s 失败: %w", file.Name, err)
			}
			defer rc.Close()

			data, err := io.ReadAll(rc)
			if err != nil {
				return nil, fmt.Errorf("读取 zip 内文件 %s 失败: %w", file.Name, err)
			}
			return data, nil
		}
	}

	// 列出 zip 中的所有文件名，便于调试
	var names []string
	for _, f := range reader.File {
		names = append(names, f.Name)
	}
	return nil, fmt.Errorf("在 zip 中未找到 %s，现有文件: %s", filename, strings.Join(names, ", "))
}

// stripPath 去掉路径前缀，只保留文件名
func stripPath(name string) string {
	parts := strings.Split(name, "/")
	return parts[len(parts)-1]
}

// defaultRestart 默认的重启实现：启动新进程后退出当前进程
func defaultRestart() {
	execPath, err := os.Executable()
	if err != nil {
		slog.Error("获取可执行文件路径失败", "error", err)
		os.Exit(1)
	}

	args := os.Args[1:]
	cmd := exec.Command(execPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Start(); err != nil {
		slog.Error("启动新进程失败", "error", err)
		os.Exit(1)
	}

	// 新进程已启动，退出当前进程
	os.Exit(0)
}

// UpdateChecker 后台更新检查器
type UpdateChecker struct {
	component Component
	logger    *slog.Logger
	interval  time.Duration
	stopCh    chan struct{}
	doneCh    chan struct{}
}

// NewUpdateChecker 创建更新检查器
func NewUpdateChecker(component Component, logger *slog.Logger) *UpdateChecker {
	return &UpdateChecker{
		component: component,
		logger:    logger,
		interval:  10 * time.Minute,
		stopCh:    make(chan struct{}),
		doneCh:    make(chan struct{}),
	}
}

// Start 启动后台更新检查协程
func (uc *UpdateChecker) Start() {
	go uc.run()
}

// Stop 停止更新检查器
func (uc *UpdateChecker) Stop() {
	close(uc.stopCh)
	<-uc.doneCh
}

// run 更新检查主循环
func (uc *UpdateChecker) run() {
	defer close(uc.doneCh)

	// 首次启动延迟 1 分钟再检查，避免影响启动速度
	select {
	case <-time.After(1 * time.Minute):
	case <-uc.stopCh:
		return
	}

	ticker := time.NewTicker(uc.interval)
	defer ticker.Stop()

	// 立即执行一次检查
	uc.check()

	for {
		select {
		case <-ticker.C:
			uc.check()
		case <-uc.stopCh:
			return
		}
	}
}

// check 执行一次更新检查
func (uc *UpdateChecker) check() {
	release, hasUpdate, err := CheckForUpdate()
	if err != nil {
		uc.logger.Warn("检查更新失败", "error", err)
		return
	}

	if !hasUpdate {
		uc.logger.Debug("当前已是最新版本", "current", Version, "latest", release.TagName)
		return
	}

	uc.logger.Info("发现新版本",
		"current", Version,
		"latest", release.TagName,
		"url", release.HTMLURL)

	// 执行更新
	if err := PerformUpdate(release, uc.component, uc.logger); err != nil {
		uc.logger.Error("自动更新失败", "error", err, "latest", release.TagName)
		return
	}

	// PerformUpdate 成功后会调用 RestartFunc 重启进程
	// 如果走到这里说明重启未成功
	uc.logger.Error("更新成功但重启未执行")
}
