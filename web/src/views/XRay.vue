<template>
  <div class="xray-page">
    <section class="hero panel">
      <div>
        <div class="muted">XRay Passive Engine</div>
        <div class="hero-title">
          <span class="status-dot" :class="status.status"></span>
          {{ statusLabel(status.status) }}
        </div>
        <div class="hero-meta">
          <span>监听 {{ status.listen || '-' }}</span>
          <span>PID {{ status.pid || '-' }}</span>
          <span>启动 {{ status.started_at ? formatDate(status.started_at) : '-' }}</span>
        </div>
      </div>
      <div class="actions">
        <el-button type="success" :icon="VideoPlay" :loading="loading" :disabled="status.status === 'running'" @click="startXRay">启动</el-button>
        <el-button type="warning" :icon="RefreshRight" :loading="loading" @click="restartXRay">重启</el-button>
        <el-button type="danger" :icon="VideoPause" :loading="loading" :disabled="status.status !== 'running'" @click="stopXRay">停止</el-button>
      </div>
    </section>

    <section v-if="status.last_error" class="error panel">
      <el-icon><Warning /></el-icon>
      <span>{{ status.last_error }}</span>
    </section>

    <section class="info-grid">
      <div class="panel info-card">
        <span>监听地址</span>
        <code>{{ status.listen || '-' }}</code>
      </div>
      <div class="panel info-card">
        <span>Webhook</span>
        <code>{{ status.webhook || '-' }}</code>
      </div>
      <div class="panel info-card">
        <span>配置文件</span>
        <code>{{ status.config || 'data/config.yaml' }}</code>
      </div>
      <div class="panel info-card">
        <span>JSON 输出</span>
        <code>{{ status.json_file || '-' }}</code>
      </div>
    </section>

    <section class="panel">
      <div class="panel-header">
        <div>
          <div class="panel-title">扫描日志</div>
          <div class="muted">stdout、stderr、代理转发失败、漏洞回调都会进入这里</div>
        </div>
        <div class="toolbar">
          <el-switch v-model="autoRefresh" active-text="自动刷新" />
          <el-button :icon="Refresh" @click="fetchAll">刷新</el-button>
        </div>
      </div>

      <div class="log-table">
        <div v-for="item in logs" :key="`${item.time}-${item.message}`" class="log-line" :class="item.level">
          <span class="time">{{ formatTime(item.time) }}</span>
          <el-tag :type="logType(item.level)" size="small" effect="plain">{{ item.level }}</el-tag>
          <code>{{ item.message }}</code>
        </div>
        <el-empty v-if="logs.length === 0" description="暂无日志" :image-size="96" />
      </div>
    </section>
  </div>
</template>

<script setup>
import { onMounted, onUnmounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Refresh, RefreshRight, VideoPause, VideoPlay } from '@element-plus/icons-vue'
import api from '../utils/api'

const status = ref({ status: 'stopped' })
const logs = ref([])
const loading = ref(false)
const autoRefresh = ref(true)

const statusLabel = (s) => ({ running: '正在监听', stopped: '已停止', error: '异常退出' }[s] || '未知')
const logType = (level) => ({ error: 'danger', warn: 'warning', info: 'info' }[level] || 'info')
const formatDate = (t) => new Date(t).toLocaleString('zh-CN', { hour12: false })
const formatTime = (t) => (t ? new Date(t).toLocaleTimeString('zh-CN', { hour12: false }) : '-')

const fetchStatus = async () => {
  const res = await api.get('/xray/status')
  if (res.code === 200) status.value = res.data || { status: 'stopped' }
}

const fetchLogs = async () => {
  const res = await api.get('/xray/logs?limit=300')
  if (res.code === 200) logs.value = res.data || []
}

const fetchAll = () => Promise.all([fetchStatus(), fetchLogs()])

const runAction = async (path, okText) => {
  loading.value = true
  try {
    const res = await api.post(path)
    if (res.code === 200) {
      ElMessage.success(okText)
    } else {
      ElMessage.error(res.message || '操作失败')
    }
  } catch (err) {
    ElMessage.error(err?.response?.data?.message || '操作失败')
  } finally {
    loading.value = false
    setTimeout(fetchAll, 600)
  }
}

const startXRay = () => runAction('/xray/start', 'XRay 已启动')
const stopXRay = () => runAction('/xray/stop', 'XRay 已停止')
const restartXRay = () => runAction('/xray/restart', 'XRay 已重启')

let timer
onMounted(() => {
  fetchAll()
  timer = setInterval(() => {
    if (autoRefresh.value) fetchAll()
  }, 2500)
})
onUnmounted(() => clearInterval(timer))
</script>

<style scoped>
.xray-page {
  display: flex;
  flex-direction: column;
  gap: 18px;
}

.hero {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 22px;
}

.hero-title {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-top: 6px;
  color: var(--app-text);
  font-size: 30px;
  font-weight: 800;
}

.hero-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 14px;
  margin-top: 12px;
  color: var(--app-muted);
}

.actions,
.toolbar {
  display: flex;
  align-items: center;
  gap: 10px;
}

.status-dot {
  width: 12px;
  height: 12px;
  border-radius: 50%;
  background: #98a2b3;
}

.status-dot.running {
  background: var(--app-success);
  box-shadow: 0 0 0 5px var(--app-success-soft);
}

.status-dot.error {
  background: var(--app-danger);
}

.error {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 14px 16px;
  color: var(--app-danger);
  border-color: #f3b6b0;
  background: var(--app-danger-soft);
}

.info-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 14px;
}

.info-card {
  min-height: 96px;
  padding: 16px;
}

.info-card span {
  display: block;
  color: var(--app-muted);
  font-size: 12px;
  margin-bottom: 10px;
}

.info-card code {
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: var(--app-text);
}

.log-table {
  max-height: calc(100vh - 430px);
  min-height: 320px;
  overflow: auto;
  padding: 10px 0;
}

.log-line {
  display: grid;
  grid-template-columns: 92px 70px 1fr;
  gap: 10px;
  align-items: start;
  padding: 8px 18px;
  border-bottom: 1px solid var(--app-border-soft);
}

.log-line:hover {
  background: #f7faff;
}

.log-line .time {
  color: var(--app-muted);
  font-variant-numeric: tabular-nums;
}

.log-line code {
  color: #344054;
  white-space: pre-wrap;
  word-break: break-word;
}

.log-line.error code {
  color: var(--app-danger);
}

@media (max-width: 1100px) {
  .info-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (max-width: 760px) {
  .hero,
  .panel-header {
    align-items: flex-start;
    flex-direction: column;
  }

  .info-grid,
  .log-line {
    grid-template-columns: 1fr;
  }
}
</style>
