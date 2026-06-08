<template>
  <div class="dashboard">
    <section class="status-strip panel">
      <div>
        <div class="eyebrow">当前引擎</div>
        <div class="engine-line">
          <span class="status-dot" :class="xrayStatus.status"></span>
          <strong>{{ statusLabel(xrayStatus.status) }}</strong>
          <span class="muted">{{ xrayStatus.listen || '-' }}</span>
        </div>
      </div>
      <div class="status-actions">
        <el-button :icon="Refresh" @click="refreshAll">刷新</el-button>
        <el-button type="primary" :icon="VideoPlay" :disabled="xrayStatus.status === 'running'" @click="startXRay">启动监听</el-button>
      </div>
    </section>

    <section class="metrics">
      <div class="metric panel">
        <div class="metric-label">在线 Agent</div>
        <div class="metric-value">{{ stats.active_agents || 0 }}</div>
      </div>
      <div class="metric panel">
        <div class="metric-label">今日流量</div>
        <div class="metric-value">{{ formatNumber(stats.today_requests) }}</div>
      </div>
      <div class="metric panel">
        <div class="metric-label">已送入 XRay</div>
        <div class="metric-value">{{ formatNumber(queueStats.total_out) }}</div>
      </div>
      <div class="metric panel danger">
        <div class="metric-label">漏洞总数</div>
        <div class="metric-value">{{ formatNumber(stats.total_vulns) }}</div>
      </div>
    </section>

    <section class="grid">
      <div class="panel">
        <div class="panel-header">
          <div>
            <div class="panel-title">扫描流</div>
            <div class="muted">接收、限流、送入 XRay 的实时情况</div>
          </div>
          <el-tag :type="queueHealth.type" effect="plain">{{ queueHealth.text }}</el-tag>
        </div>
        <div class="flow-body">
          <div class="queue-bar">
            <div :style="{ width: `${queueUsagePct}%` }"></div>
          </div>
          <div class="flow-grid">
            <div>
              <span>待处理</span>
              <strong>{{ formatNumber(queueStats.length) }} / {{ formatNumber(queueStats.capacity) }}</strong>
            </div>
            <div>
              <span>接收速率</span>
              <strong>{{ fixed(queueStats.rate_in) }}/s</strong>
            </div>
            <div>
              <span>送入速率</span>
              <strong>{{ fixed(queueStats.rate_out) }}/s</strong>
            </div>
            <div>
              <span>丢弃</span>
              <strong :class="{ bad: queueStats.total_dropped > 0 }">{{ formatNumber(queueStats.total_dropped) }}</strong>
            </div>
          </div>
        </div>
      </div>

      <div class="panel">
        <div class="panel-header">
          <div>
            <div class="panel-title">漏洞分布</div>
            <div class="muted">按风险等级统计</div>
          </div>
        </div>
        <div class="severity-list">
          <div class="severity high">
            <span>高危</span>
            <el-progress :percentage="percent(stats.high_vulns)" :stroke-width="10" color="#ef4444" />
            <strong>{{ stats.high_vulns || 0 }}</strong>
          </div>
          <div class="severity medium">
            <span>中危</span>
            <el-progress :percentage="percent(stats.medium_vulns)" :stroke-width="10" color="#f59e0b" />
            <strong>{{ stats.medium_vulns || 0 }}</strong>
          </div>
          <div class="severity low">
            <span>低危</span>
            <el-progress :percentage="percent(stats.low_vulns)" :stroke-width="10" color="#22c55e" />
            <strong>{{ stats.low_vulns || 0 }}</strong>
          </div>
        </div>
      </div>
    </section>

    <section class="panel">
      <div class="panel-header">
        <div>
          <div class="panel-title">最近 XRay 日志</div>
          <div class="muted">{{ xrayStatus.last_error || '启动、监听、转发失败和漏洞回调都会显示在这里' }}</div>
        </div>
        <el-button :icon="Document" @click="$router.push('/xray')">查看详情</el-button>
      </div>
      <div class="log-preview">
        <div v-for="item in logs.slice(-8)" :key="`${item.time}-${item.message}`" class="log-row">
          <span>{{ formatTime(item.time) }}</span>
          <el-tag :type="logType(item.level)" size="small" effect="plain">{{ item.level }}</el-tag>
          <code>{{ item.message }}</code>
        </div>
        <el-empty v-if="logs.length === 0" description="暂无日志" :image-size="72" />
      </div>
    </section>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Document, Refresh, VideoPlay } from '@element-plus/icons-vue'
import api from '../utils/api'

const stats = ref({})
const queueStats = ref({})
const xrayStatus = ref({ status: 'stopped' })
const logs = ref([])

const queueUsagePct = computed(() => Math.min(100, Math.max(0, queueStats.value.usage_pct || 0)))
const queueHealth = computed(() => {
  if ((queueStats.value.total_dropped || 0) > 0) return { type: 'danger', text: '有丢弃' }
  if (queueUsagePct.value > 70) return { type: 'warning', text: '压力偏高' }
  return { type: 'success', text: '正常' }
})

const formatNumber = (n) => Number(n || 0).toLocaleString()
const fixed = (n) => Number(n || 0).toFixed(1)
const percent = (n) => stats.value.total_vulns ? Math.round((Number(n || 0) / stats.value.total_vulns) * 100) : 0
const statusLabel = (s) => ({ running: '监听中', stopped: '未运行', error: '异常' }[s] || '未知')
const logType = (level) => ({ error: 'danger', warn: 'warning', info: 'info' }[level] || 'info')
const formatTime = (t) => (t ? new Date(t).toLocaleTimeString('zh-CN', { hour12: false }) : '-')

const fetchStats = async () => {
  const res = await api.get('/vulns/stats')
  if (res.code === 200) stats.value = res.data || {}
}

const fetchQueue = async () => {
  const res = await api.get('/queue/stats')
  if (res.code === 200) queueStats.value = res.data?.xray_pipe || {}
}

const fetchXRay = async () => {
  const [statusRes, logRes] = await Promise.all([
    api.get('/xray/status'),
    api.get('/xray/logs?limit=80'),
  ])
  if (statusRes.code === 200) xrayStatus.value = statusRes.data || { status: 'stopped' }
  if (logRes.code === 200) logs.value = logRes.data || []
}

const refreshAll = () => Promise.all([fetchStats(), fetchQueue(), fetchXRay()])

const startXRay = async () => {
  const res = await api.post('/xray/start')
  if (res.code === 200) {
    ElMessage.success('XRay 已启动')
    refreshAll()
  } else {
    ElMessage.error(res.message || '启动失败')
  }
}

let timer
onMounted(() => {
  refreshAll()
  timer = setInterval(refreshAll, 3000)
})
onUnmounted(() => clearInterval(timer))
</script>

<style scoped>
.dashboard {
  display: flex;
  flex-direction: column;
  gap: 18px;
}

.status-strip {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 18px;
}

.eyebrow,
.metric-label {
  color: #8b949e;
  font-size: 12px;
}

.engine-line {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-top: 6px;
  font-size: 20px;
}

.status-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: #6b7280;
}

.status-dot.running {
  background: #22c55e;
  box-shadow: 0 0 0 4px rgba(34, 197, 94, .12);
}

.status-dot.error {
  background: #ef4444;
}

.status-actions {
  display: flex;
  gap: 10px;
}

.metrics {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 14px;
}

.metric {
  padding: 16px;
}

.metric-value {
  margin-top: 8px;
  color: #f8fafc;
  font-size: 30px;
  font-weight: 800;
}

.metric.danger .metric-value {
  color: #f87171;
}

.grid {
  display: grid;
  grid-template-columns: 1.25fr .75fr;
  gap: 18px;
}

.flow-body,
.severity-list,
.log-preview {
  padding: 18px;
}

.queue-bar {
  height: 10px;
  overflow: hidden;
  background: #0f1720;
  border-radius: 999px;
}

.queue-bar div {
  height: 100%;
  background: linear-gradient(90deg, #14b8a6, #f59e0b);
  transition: width .25s ease;
}

.flow-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 10px;
  margin-top: 18px;
}

.flow-grid div {
  padding: 12px;
  background: #101419;
  border: 1px solid #2a2f36;
  border-radius: 8px;
}

.flow-grid span,
.severity span {
  display: block;
  color: #8b949e;
  font-size: 12px;
  margin-bottom: 6px;
}

.flow-grid strong,
.severity strong {
  color: #f8fafc;
}

.bad {
  color: #f87171 !important;
}

.severity {
  display: grid;
  grid-template-columns: 48px 1fr 42px;
  align-items: center;
  gap: 10px;
  margin-bottom: 18px;
}

.log-row {
  display: grid;
  grid-template-columns: 86px 62px 1fr;
  gap: 10px;
  align-items: center;
  min-height: 32px;
  color: #cbd5e1;
}

.log-row code {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: #d1d5db;
}

@media (max-width: 980px) {
  .metrics,
  .grid,
  .flow-grid {
    grid-template-columns: 1fr;
  }

  .status-strip {
    align-items: flex-start;
    flex-direction: column;
  }
}
</style>
