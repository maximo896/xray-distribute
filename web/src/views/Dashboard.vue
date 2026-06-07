<template>
  <div class="dashboard">
    <h2 class="page-title">仪表盘</h2>

    <!-- 统计卡片 -->
    <el-row :gutter="20" class="stat-row">
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-icon" style="background: linear-gradient(135deg, #409eff, #79bbff)">
            <el-icon :size="28"><Connection /></el-icon>
          </div>
          <div class="stat-info">
            <div class="stat-value">{{ stats.active_agents }}</div>
            <div class="stat-label">在线Agent</div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-icon" style="background: linear-gradient(135deg, #67c23a, #95d475)">
            <el-icon :size="28"><Promotion /></el-icon>
          </div>
          <div class="stat-info">
            <div class="stat-value">{{ formatNumber(stats.today_requests) }}</div>
            <div class="stat-label">今日流量</div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-icon" style="background: linear-gradient(135deg, #f56c6c, #fab6b6)">
            <el-icon :size="28"><Warning /></el-icon>
          </div>
          <div class="stat-info">
            <div class="stat-value">{{ stats.total_vulns }}</div>
            <div class="stat-label">漏洞总数</div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-icon" style="background: linear-gradient(135deg, #e6a23c, #eebe77)">
            <el-icon :size="28"><TrendCharts /></el-icon>
          </div>
          <div class="stat-info">
            <div class="stat-value">{{ stats.high_vulns }}</div>
            <div class="stat-label">高危漏洞</div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 队列监控 -->
    <el-row :gutter="20" style="margin-top: 20px">
      <el-col :span="12">
        <el-card shadow="hover">
          <template #header>
            <div style="display:flex;justify-content:space-between;align-items:center">
              <span>XRay管道队列</span>
              <el-tag :type="queueHealth" size="small">{{ queueHealthText }}</el-tag>
            </div>
          </template>
          <div class="queue-monitor">
            <div class="queue-bar-wrap">
              <div class="queue-bar" :style="{ width: queueUsagePct + '%' }" :class="queueBarClass"></div>
            </div>
            <div class="queue-detail">
              <div class="queue-detail-item">
                <span class="queue-label">队列深度</span>
                <span class="queue-value">{{ formatNumber(queueStats.length) }} / {{ formatNumber(queueStats.capacity) }}</span>
              </div>
              <div class="queue-detail-item">
                <span class="queue-label">使用率</span>
                <span class="queue-value">{{ queueUsagePct.toFixed(1) }}%</span>
              </div>
              <div class="queue-detail-item">
                <span class="queue-label">入队速率</span>
                <span class="queue-value">{{ queueStats.rate_in?.toFixed(1) || 0 }} /s</span>
              </div>
              <div class="queue-detail-item">
                <span class="queue-label">出队速率</span>
                <span class="queue-value">{{ queueStats.rate_out?.toFixed(1) || 0 }} /s</span>
              </div>
              <div class="queue-detail-item">
                <span class="queue-label">总入队</span>
                <span class="queue-value">{{ formatNumber(queueStats.total_in) }}</span>
              </div>
              <div class="queue-detail-item">
                <span class="queue-label">总丢弃</span>
                <span class="queue-value" :style="{ color: queueStats.total_dropped > 0 ? '#f56c6c' : '' }">{{ formatNumber(queueStats.total_dropped) }}</span>
              </div>
            </div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="12">
        <el-card shadow="hover">
          <template #header>
            <div style="display:flex;justify-content:space-between;align-items:center">
              <span>流速控制</span>
              <el-tag :type="flowCtrl.enabled ? 'success' : 'info'" size="small">{{ flowCtrl.enabled ? '已启用' : '未启用' }}</el-tag>
            </div>
          </template>
          <div class="flow-ctrl">
            <div class="flow-ctrl-item">
              <span class="queue-label">当前QPS限制</span>
              <span class="queue-value" style="font-size:24px;font-weight:700;color:#409eff">{{ flowCtrl.current_qps || 0 }}</span>
            </div>
            <div class="flow-ctrl-item">
              <span class="queue-label">最大QPS</span>
              <span class="queue-value">{{ flowCtrl.max_qps || 0 }}</span>
            </div>
            <div class="flow-ctrl-item">
              <span class="queue-label">自适应模式</span>
              <el-tag :type="flowCtrl.adaptive ? 'success' : 'info'" size="small">{{ flowCtrl.adaptive ? '开启' : '关闭' }}</el-tag>
            </div>
            <el-divider />
            <div class="flow-ctrl-item">
              <span class="queue-label">手动调整QPS</span>
              <div style="display:flex;gap:8px;align-items:center;margin-top:8px">
                <el-input-number v-model="manualQPS" :min="10" :max="5000" :step="50" size="small" />
                <el-button type="primary" size="small" @click="setQPS">应用</el-button>
              </div>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 漏洞等级分布 -->
    <el-row :gutter="20" style="margin-top: 20px">
      <el-col :span="12">
        <el-card shadow="hover">
          <template #header>
            <span>漏洞等级分布</span>
          </template>
          <div class="severity-chart">
            <div class="severity-item">
              <span class="severity-label">高危</span>
              <el-progress :percentage="highPercent" :stroke-width="20" color="#f56c6c" />
              <span class="severity-count">{{ stats.high_vulns }}</span>
            </div>
            <div class="severity-item">
              <span class="severity-label">中危</span>
              <el-progress :percentage="mediumPercent" :stroke-width="20" color="#e6a23c" />
              <span class="severity-count">{{ stats.medium_vulns }}</span>
            </div>
            <div class="severity-item">
              <span class="severity-label">低危</span>
              <el-progress :percentage="lowPercent" :stroke-width="20" color="#67c23a" />
              <span class="severity-count">{{ stats.low_vulns }}</span>
            </div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="12">
        <el-card shadow="hover">
          <template #header>
            <span>流量概览</span>
          </template>
          <div class="traffic-overview">
            <div class="traffic-item">
              <el-icon :size="40" color="#409eff"><Promotion /></el-icon>
              <div>
                <div class="traffic-value">{{ formatNumber(stats.total_requests) }}</div>
                <div class="traffic-label">总流量数</div>
              </div>
            </div>
            <el-divider />
            <div class="traffic-item">
              <el-icon :size="40" color="#67c23a"><Promotion /></el-icon>
              <div>
                <div class="traffic-value">{{ formatNumber(stats.today_requests) }}</div>
                <div class="traffic-label">今日流量</div>
              </div>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { ElMessage } from 'element-plus'
import api from '../utils/api'

const stats = ref({
  total_requests: 0,
  today_requests: 0,
  total_vulns: 0,
  high_vulns: 0,
  medium_vulns: 0,
  low_vulns: 0,
  active_agents: 0,
})

const queueStats = ref({
  length: 0,
  capacity: 0,
  usage_pct: 0,
  total_in: 0,
  total_out: 0,
  total_dropped: 0,
  rate_in: 0,
  rate_out: 0,
})

const flowCtrl = ref({
  enabled: false,
  current_qps: 0,
  max_qps: 0,
  adaptive: false,
})

const manualQPS = ref(500)

const queueUsagePct = computed(() => queueStats.value.usage_pct || 0)

const queueHealth = computed(() => {
  const pct = queueUsagePct.value
  if (pct > 80) return 'danger'
  if (pct > 60) return 'warning'
  return 'success'
})

const queueHealthText = computed(() => {
  const pct = queueUsagePct.value
  if (pct > 80) return '危险'
  if (pct > 60) return '偏高'
  return '正常'
})

const queueBarClass = computed(() => {
  const pct = queueUsagePct.value
  if (pct > 80) return 'bar-danger'
  if (pct > 60) return 'bar-warning'
  return 'bar-ok'
})

const highPercent = computed(() => {
  if (!stats.value.total_vulns) return 0
  return Math.round((stats.value.high_vulns / stats.value.total_vulns) * 100)
})

const mediumPercent = computed(() => {
  if (!stats.value.total_vulns) return 0
  return Math.round((stats.value.medium_vulns / stats.value.total_vulns) * 100)
})

const lowPercent = computed(() => {
  if (!stats.value.total_vulns) return 0
  return Math.round((stats.value.low_vulns / stats.value.total_vulns) * 100)
})

const formatNumber = (n) => {
  if (!n) return '0'
  return n.toLocaleString()
}

const setQPS = async () => {
  try {
    const res = await api.post('/queue/flow', { max_qps: manualQPS.value })
    if (res.code === 200) {
      ElMessage.success(`QPS已调整为 ${manualQPS.value}`)
      fetchQueueStats()
    }
  } catch {}
}

const fetchStats = async () => {
  try {
    const res = await api.get('/vulns/stats')
    if (res.code === 200) {
      stats.value = res.data
    }
  } catch {}
}

const fetchQueueStats = async () => {
  try {
    const res = await api.get('/queue/stats')
    if (res.code === 200) {
      queueStats.value = res.data.xray_pipe || {}
      flowCtrl.value = res.data.flow_ctrl || {}
    }
  } catch {}
}

let timer = null
onMounted(() => {
  fetchStats()
  fetchQueueStats()
  timer = setInterval(() => {
    fetchStats()
    fetchQueueStats()
  }, 3000) // 队列3秒刷新
})

onUnmounted(() => {
  if (timer) clearInterval(timer)
})
</script>

<style scoped>
.page-title {
  font-size: 22px;
  font-weight: 600;
  margin-bottom: 20px;
  color: #e0e0e0;
}
.stat-card {
  display: flex;
  align-items: center;
  padding: 0;
}
.stat-card :deep(.el-card__body) {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 20px;
  width: 100%;
}
.stat-icon {
  width: 56px;
  height: 56px;
  border-radius: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: white;
  flex-shrink: 0;
}
.stat-value {
  font-size: 28px;
  font-weight: 700;
  color: #e0e0e0;
}
.stat-label {
  font-size: 13px;
  color: #a0a3bd;
  margin-top: 4px;
}
.severity-chart {
  display: flex;
  flex-direction: column;
  gap: 20px;
  padding: 10px 0;
}
.severity-item {
  display: flex;
  align-items: center;
  gap: 12px;
}
.severity-label {
  width: 40px;
  font-size: 14px;
  color: #a0a3bd;
}
.severity-item :deep(.el-progress) {
  flex: 1;
}
.severity-count {
  width: 40px;
  text-align: right;
  font-size: 16px;
  font-weight: 600;
  color: #e0e0e0;
}
.traffic-overview {
  padding: 10px 0;
}
.traffic-item {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 10px 0;
}
.traffic-value {
  font-size: 24px;
  font-weight: 700;
  color: #e0e0e0;
}
.traffic-label {
  font-size: 13px;
  color: #a0a3bd;
}
.queue-monitor {
  padding: 10px 0;
}
.queue-bar-wrap {
  height: 24px;
  background: #1d1e2c;
  border-radius: 12px;
  overflow: hidden;
  margin-bottom: 16px;
}
.queue-bar {
  height: 100%;
  border-radius: 12px;
  transition: width 0.5s ease, background 0.3s ease;
  min-width: 2px;
}
.queue-bar.bar-ok {
  background: linear-gradient(90deg, #67c23a, #95d475);
}
.queue-bar.bar-warning {
  background: linear-gradient(90deg, #e6a23c, #eebe77);
}
.queue-bar.bar-danger {
  background: linear-gradient(90deg, #f56c6c, #fab6b6);
  animation: pulse 1.5s infinite;
}
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.7; }
}
.queue-detail {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
}
.queue-detail-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 6px 12px;
  background: #1d1e2c;
  border-radius: 6px;
}
.queue-label {
  font-size: 13px;
  color: #a0a3bd;
}
.queue-value {
  font-size: 14px;
  font-weight: 600;
  color: #e0e0e0;
}
.flow-ctrl {
  padding: 10px 0;
}
.flow-ctrl-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px 0;
}
</style>
