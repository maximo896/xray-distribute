<template>
  <div class="xray-page">
    <h2 class="page-title">XRay管理</h2>

    <!-- XRay状态卡片 -->
    <el-card shadow="hover" style="margin-bottom: 20px">
      <template #header>
        <div style="display: flex; justify-content: space-between; align-items: center">
          <span>XRay扫描引擎</span>
          <div>
            <el-button type="success" @click="startXRay" :loading="actionLoading" :disabled="status?.status === 'running'">
              <el-icon><VideoPlay /></el-icon>启动
            </el-button>
            <el-button type="danger" @click="stopXRay" :loading="actionLoading" :disabled="status?.status !== 'running'">
              <el-icon><VideoPause /></el-icon>停止
            </el-button>
            <el-button type="warning" @click="restartXRay" :loading="actionLoading">
              <el-icon><RefreshRight /></el-icon>重启
            </el-button>
          </div>
        </div>
      </template>

      <el-descriptions :column="3" border>
        <el-descriptions-item label="运行状态">
          <el-tag :type="status?.status === 'running' ? 'success' : status?.status === 'error' ? 'danger' : 'info'" effect="dark">
            {{ statusLabel(status?.status) }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="进程PID">
          {{ status?.pid || '-' }}
        </el-descriptions-item>
        <el-descriptions-item label="启动时间">
          {{ status?.started_at ? formatTime(status.started_at) : '-' }}
        </el-descriptions-item>
      </el-descriptions>
    </el-card>

    <!-- XRay工作模式说明 -->
    <el-row :gutter="20">
      <el-col :span="12">
        <el-card shadow="hover">
          <template #header>
            <span>被动扫描模式</span>
          </template>
          <div class="mode-desc">
            <el-icon :size="48" color="#409eff"><Connection /></el-icon>
            <p>XRay以被动扫描模式运行，监听 <code>127.0.0.1:7777</code></p>
            <p>Agent镜像的流量通过HTTP代理方式发送到XRay</p>
            <p>发现漏洞后自动通过Webhook通知</p>
            <el-tag type="success" effect="dark" style="margin-top: 12px">当前模式</el-tag>
          </div>
        </el-card>
      </el-col>
      <el-col :span="12">
        <el-card shadow="hover">
          <template #header>
            <span>工作流程</span>
          </template>
          <div class="flow-steps">
            <div class="flow-step">
              <el-icon :size="24" color="#409eff"><Promotion /></el-icon>
              <span>业务流量</span>
            </div>
            <el-icon class="flow-arrow"><ArrowRight /></el-icon>
            <div class="flow-step">
              <el-icon :size="24" color="#67c23a"><Connection /></el-icon>
              <span>Agent镜像</span>
            </div>
            <el-icon class="flow-arrow"><ArrowRight /></el-icon>
            <div class="flow-step">
              <el-icon :size="24" color="#e6a23c"><Cpu /></el-icon>
              <span>XRay扫描</span>
            </div>
            <el-icon class="flow-arrow"><ArrowRight /></el-icon>
            <div class="flow-step">
              <el-icon :size="24" color="#f56c6c"><Bell /></el-icon>
              <span>漏洞通知</span>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import api from '../utils/api'
import { ElMessage } from 'element-plus'

const status = ref(null)
const actionLoading = ref(false)

const statusLabel = (s) => ({ running: '运行中', stopped: '已停止', error: '异常' }[s] || '未知')

const formatTime = (t) => {
  if (!t) return '-'
  return new Date(t).toLocaleString('zh-CN')
}

const fetchStatus = async () => {
  try {
    const res = await api.get('/xray/status')
    if (res.code === 200) {
      status.value = res.data
    }
  } catch {}
}

const startXRay = async () => {
  actionLoading.value = true
  try {
    const res = await api.post('/xray/start')
    if (res.code === 200) {
      ElMessage.success('XRay启动成功')
      setTimeout(fetchStatus, 2000)
    } else {
      ElMessage.error(res.message)
    }
  } catch {
    ElMessage.error('启动失败')
  } finally {
    actionLoading.value = false
  }
}

const stopXRay = async () => {
  actionLoading.value = true
  try {
    const res = await api.post('/xray/stop')
    if (res.code === 200) {
      ElMessage.success('XRay已停止')
      fetchStatus()
    } else {
      ElMessage.error(res.message)
    }
  } catch {
    ElMessage.error('停止失败')
  } finally {
    actionLoading.value = false
  }
}

const restartXRay = async () => {
  actionLoading.value = true
  try {
    const res = await api.post('/xray/restart')
    if (res.code === 200) {
      ElMessage.success('XRay重启成功')
      setTimeout(fetchStatus, 2000)
    } else {
      ElMessage.error(res.message)
    }
  } catch {
    ElMessage.error('重启失败')
  } finally {
    actionLoading.value = false
  }
}

onMounted(() => {
  fetchStatus()
  setInterval(fetchStatus, 5000)
})
</script>

<style scoped>
.page-title {
  font-size: 22px;
  font-weight: 600;
  margin-bottom: 20px;
  color: #e0e0e0;
}
.mode-desc {
  text-align: center;
  padding: 20px 0;
}
.mode-desc p {
  margin: 8px 0;
  color: #a0a3bd;
  font-size: 14px;
}
.mode-desc code {
  background: #232440;
  padding: 2px 8px;
  border-radius: 4px;
  color: #409eff;
}
.flow-steps {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 12px;
  padding: 30px 0;
}
.flow-step {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
}
.flow-step span {
  font-size: 13px;
  color: #a0a3bd;
}
.flow-arrow {
  color: #409eff;
  font-size: 20px;
}
</style>
