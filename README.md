# XRay-Distribute

分布式被动漏洞扫描平台，基于长亭 XRay 引擎。Server-Agent 架构，Agent 部署在业务服务器旁，通过流量镜像将业务流量转发到 Server 端的 XRay 进行被动漏洞扫描，支持 OOB 反连检测和 Webhook 告警通知。

## 架构

```
浏览器 --> Agent(:9090) --镜像--> Server(:8081) --> XRay(:7777)
              |                                              |
              +--转发--> 目标业务                    XRay webhook-output
                                                             |
                                                  Server 漏洞存储 + Webhook通知
                                                             |
                                                  Web面板(:8090) <--- 用户
```

## 快速开始

### Server 部署

1. 下载 `xray-distribute-server.zip` 并解压到服务器
2. 修改 `config.yaml` 中的 `token`
3. 启动：

```bash
chmod +x start.sh && ./start.sh
```

4. 启动后会输出 Agent 连接命令：

```
========================================
  XRay-Distribute Server Started
========================================
  Web Panel:  http://localhost:8090
  API:        http://localhost:8081

  Agent连接命令（复制给Agent端执行）:
  agent xray://your-secret-token@192.168.1.100:8081
========================================
```

5. 打开 `http://your-server:8090` 访问 Web 面板，输入 token 登录

### Agent 使用

1. 下载 `xray-distribute-local.zip` 并解压
2. 首次运行，复制 Server 输出的连接命令：

```bash
# Windows
agent.exe xray://your-secret-token@192.168.1.100:8081

# Linux
./agent xray://your-secret-token@192.168.1.100:8081
```

3. 配置自动保存，之后直接运行即可：

```bash
agent.exe    # Windows
./agent      # Linux
```

4. 将浏览器代理设为 `127.0.0.1:9090`，正常浏览业务即可自动扫描

> 首次使用 HTTPS 站点时，Agent 会自动生成 CA 证书，需要将 `certs/ca.crt` 导入到设备的信任证书列表中。

## 功能特性

- **全协议流量镜像** - HTTP/1.x、HTTP/2、WebSocket、TLS MITM
- **OOB 反连检测** - 支持 interactsh 公共服务器（零配置）和本地反连模式
- **Web 管理面板** - 漏洞查看、Agent 管理、XRay 状态监控
- **Webhook 告警** - 支持钉钉、企业微信、飞书、自定义 HTTP
- **流量限速** - 内置令牌桶限流，防止 XRay 过载
- **SQLite 流量库** - 按日滚动，7 天自动清理

## Server 配置

```yaml
server:
  http: ":8090"       # Web面板端口
  api: ":8081"        # Agent连接API端口
  token: "your-secret-token"

xray:
  binary: "data/xray"
  data_dir: "./data"
  listen: "0.0.0.0:7777"

reverse:
  enabled: true
  mode: "interactsh"                    # interactsh 或 local
  interactsh_server: "https://oast.fun"

webhook:
  enabled: true
  min_severity: "medium"

db:
  type: "sqlite"
  dsn: "./data/xray-distribute.db"
```

## 从源码构建

```bash
# 构建前端
cd web && npm install && npm run build && cd ..

# 构建 Server
go build -o xray-distribute ./cmd/server/

# 构建 Agent
go build -o agent ./cmd/agent/
```

## License

MIT
