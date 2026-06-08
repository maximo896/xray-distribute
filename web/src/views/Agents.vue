<template>
  <div class="agents-page">
    <h2 class="page-title">Agent节点</h2>

    <el-card shadow="hover">
      <el-table :data="agents" stripe style="width: 100%" v-loading="loading">
        <el-table-column prop="id" label="ID" width="180" />
        <el-table-column prop="name" label="名称" width="160" />
        <el-table-column prop="ip" label="IP地址" width="160" />
        <el-table-column prop="status" label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="row.status === 'online' ? 'success' : 'danger'" size="small" effect="dark">
              {{ row.status === 'online' ? '在线' : '离线' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="last_heartbeat" label="最后心跳" width="200">
          <template #default="{ row }">
            {{ formatTime(row.last_heartbeat) }}
          </template>
        </el-table-column>
        <el-table-column prop="created_at" label="注册时间" width="200">
          <template #default="{ row }">
            {{ formatTime(row.created_at) }}
          </template>
        </el-table-column>
        <el-table-column label="操作" width="100" fixed="right">
          <template #default="{ row }">
            <el-popconfirm title="确定删除该Agent?" @confirm="deleteAgent(row.id)">
              <template #reference>
                <el-button type="danger" link size="small">删除</el-button>
              </template>
            </el-popconfirm>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- CA证书下载 -->
    <el-card shadow="hover" style="margin-top: 20px">
      <template #header>
        <div style="display: flex; justify-content: space-between; align-items: center">
          <span>CA证书（HTTPS抓包必需）</span>
        </div>
      </template>
      <div class="cert-guide">
        <el-alert
          type="warning"
          :closable="false"
          show-icon
          style="margin-bottom: 16px"
        >
          <template #title>
            要拦截HTTPS流量，必须将CA证书安装到客户端设备的信任列表中。未安装证书时，HTTPS请求会报证书错误。
          </template>
        </el-alert>

        <el-row :gutter="20">
          <el-col :span="12">
            <div class="cert-download-card">
              <el-icon :size="40" color="#1f6feb"><Document /></el-icon>
              <h4>PEM格式 (.crt)</h4>
              <p>适用于：Windows、Linux、macOS</p>
              <el-button type="primary" @click="downloadCert('crt')">
                <el-icon><Download /></el-icon>下载 CA 证书 (.crt)
              </el-button>
            </div>
          </el-col>
          <el-col :span="12">
            <div class="cert-download-card">
              <el-icon :size="40" color="#198754"><Iphone /></el-icon>
              <h4>DER格式 (.cer)</h4>
              <p>适用于：iOS、Android 手机导入</p>
              <el-button type="success" @click="downloadCert('der')">
                <el-icon><Download /></el-icon>下载 CA 证书 (.cer)
              </el-button>
            </div>
          </el-col>
        </el-row>

        <el-divider />

        <h4 style="color: var(--app-text); margin-bottom: 12px">证书安装指南</h4>
        <el-collapse>
          <el-collapse-item title="iOS (iPhone/iPad)" name="ios">
            <ol class="install-steps">
              <li>点击上方下载 <code>.cer</code> 证书</li>
              <li>打开 <strong>设置 → 通用 → VPN与设备管理</strong>，安装下载的描述文件</li>
              <li>打开 <strong>设置 → 通用 → 关于本机 → 证书信任设置</strong>，启用对该证书的完全信任</li>
              <li>配置WiFi代理指向Agent地址和端口</li>
            </ol>
          </el-collapse-item>
          <el-collapse-item title="Android" name="android">
            <ol class="install-steps">
              <li>点击上方下载 <code>.cer</code> 证书</li>
              <li>打开 <strong>设置 → 安全 → 加密与凭据 → 安装证书 → CA证书</strong></li>
              <li>选择下载的证书文件安装</li>
              <li>配置WiFi代理指向Agent地址和端口</li>
            </ol>
          </el-collapse-item>
          <el-collapse-item title="Windows" name="windows">
            <ol class="install-steps">
              <li>点击上方下载 <code>.crt</code> 证书</li>
              <li>双击证书文件 → 安装证书 → 本地计算机 → 将所有证书放入"受信任的根证书颁发机构"</li>
              <li>配置系统代理指向Agent地址和端口</li>
            </ol>
          </el-collapse-item>
          <el-collapse-item title="macOS" name="macos">
            <ol class="install-steps">
              <li>点击上方下载 <code>.crt</code> 证书</li>
              <li>双击证书文件，添加到钥匙串</li>
              <li>在钥匙串访问中找到该证书，双击 → 信任 → 使用此证书时 → 始终信任</li>
              <li>配置系统代理指向Agent地址和端口</li>
            </ol>
          </el-collapse-item>
        </el-collapse>
      </div>
    </el-card>

    <!-- Agent接入说明 -->
    <el-card shadow="hover" style="margin-top: 20px">
      <template #header>
        <span>Agent接入说明</span>
      </template>
      <div class="guide">
        <p>1. 在需要审计流量的服务器上部署 Agent</p>
        <p>2. 配置 <code>agent.yaml</code>：</p>
        <pre class="code-block">server:
  address: "http://{{ serverAddress }}:8081"
  token: "{{ currentToken }}"
proxy:
  listen: ":9090"
  target: "http://localhost:8080"  # 你的业务服务地址
  cert_dir: "./certs"              # CA证书存储目录</pre>
        <p>3. 启动 Agent：<code>./agent -config agent.yaml</code></p>
        <p>4. 将流量指向 Agent 监听端口（如 <code>http://localhost:9090</code>）</p>
        <p>5. Agent 会将流量原样转发到目标，同时复制一份发送到远端 XRay 进行审计</p>
        <p>6. 首次启动会自动生成 CA 证书，保存在 <code>certs/ca.crt</code></p>
        <p>7. 如需抓取 HTTPS 流量，将 <code>certs/ca.crt</code> 安装到客户端设备</p>
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import api from '../utils/api'

const agents = ref([])
const loading = ref(false)
const serverAddress = ref(window.location.hostname)
const currentToken = ref(localStorage.getItem('xray-token') || 'your-secret-token')

const formatTime = (t) => {
  if (!t) return '-'
  return new Date(t).toLocaleString('zh-CN')
}

const fetchAgents = async () => {
  loading.value = true
  try {
    const res = await api.get('/agents')
    if (res.code === 200) {
      agents.value = res.data || []
    }
  } catch {} finally {
    loading.value = false
  }
}

const deleteAgent = async (id) => {
  try {
    await api.delete('/agents', { params: { id } })
    fetchAgents()
  } catch {}
}

const downloadCert = (format) => {
  const url = format === 'der' ? '/api/v1/cert/ca.der' : '/api/v1/cert/ca.crt'
  const link = document.createElement('a')
  link.href = url
  link.download = format === 'der' ? 'xray-distribute-ca.cer' : 'xray-distribute-ca.crt'
  link.click()
}

onMounted(fetchAgents)
</script>

<style scoped>
.page-title {
  font-size: 22px;
  font-weight: 600;
  margin-bottom: 20px;
  color: var(--app-text);
}
.cert-download-card {
  text-align: center;
  padding: 24px;
  border-radius: 8px;
  background: var(--app-surface-soft);
  border: 1px solid var(--app-border-soft);
}
.cert-download-card h4 {
  margin: 12px 0 4px;
  color: var(--app-text);
  font-size: 15px;
}
.cert-download-card p {
  color: var(--app-muted);
  font-size: 13px;
  margin-bottom: 16px;
}
.install-steps {
  padding-left: 20px;
  color: #344054;
  line-height: 2;
}
.install-steps code {
  background: var(--app-code-bg);
  padding: 2px 6px;
  border-radius: 4px;
  color: var(--app-primary);
  font-size: 13px;
}
.guide p {
  margin: 8px 0;
  color: #344054;
  line-height: 1.8;
}
.guide code {
  background: var(--app-code-bg);
  padding: 2px 8px;
  border-radius: 4px;
  color: var(--app-primary);
  font-size: 13px;
}
.code-block {
  background: var(--app-code-bg);
  border: 1px solid var(--app-border-soft);
  border-radius: 6px;
  padding: 12px;
  font-size: 13px;
  line-height: 1.6;
  color: #344054;
  margin: 8px 0;
}
</style>
