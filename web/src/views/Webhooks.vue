<template>
  <div class="webhooks-page">
    <h2 class="page-title">Webhook通知</h2>

    <!-- 添加Webhook -->
    <el-card shadow="hover" style="margin-bottom: 20px">
      <template #header>
        <div style="display: flex; justify-content: space-between; align-items: center">
          <span>Webhook配置</span>
          <el-button type="primary" @click="showAddDialog">
            <el-icon><Plus /></el-icon>添加Webhook
          </el-button>
        </div>
      </template>

      <el-table :data="webhooks" stripe style="width: 100%" v-loading="loading">
        <el-table-column prop="name" label="名称" width="160" />
        <el-table-column prop="type" label="类型" width="120">
          <template #default="{ row }">
            <el-tag size="small">{{ typeLabel(row.type) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="url" label="URL" min-width="300" show-overflow-tooltip />
        <el-table-column prop="enabled" label="状态" width="80">
          <template #default="{ row }">
            <el-tag :type="row.enabled ? 'success' : 'info'" size="small" effect="dark">
              {{ row.enabled ? '启用' : '禁用' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="180" fixed="right">
          <template #default="{ row }">
            <el-button type="primary" link size="small" @click="testWebhook(row.id)">测试</el-button>
            <el-button type="warning" link size="small" @click="editWebhook(row)">编辑</el-button>
            <el-popconfirm title="确定删除?" @confirm="deleteWebhook(row.id)">
              <template #reference>
                <el-button type="danger" link size="small">删除</el-button>
              </template>
            </el-popconfirm>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- 支持的通知类型 -->
    <el-card shadow="hover">
      <template #header>
        <span>支持的通知类型</span>
      </template>
      <el-row :gutter="20">
        <el-col :span="6" v-for="item in supportedTypes" :key="item.type">
          <div class="type-card">
            <el-icon :size="32" :color="item.color"><component :is="item.icon" /></el-icon>
            <div class="type-name">{{ item.name }}</div>
            <div class="type-desc">{{ item.desc }}</div>
          </div>
        </el-col>
      </el-row>
    </el-card>

    <!-- 添加/编辑弹窗 -->
    <el-dialog v-model="dialogVisible" :title="isEdit ? '编辑Webhook' : '添加Webhook'" width="500px">
      <el-form :model="form" label-width="80px">
        <el-form-item label="名称">
          <el-input v-model="form.name" placeholder="如：安全团队群" />
        </el-form-item>
        <el-form-item label="类型">
          <el-select v-model="form.type" placeholder="选择通知类型" style="width: 100%">
            <el-option label="钉钉" value="dingtalk" />
            <el-option label="企业微信" value="wecom" />
            <el-option label="飞书" value="lark" />
            <el-option label="自定义" value="custom" />
          </el-select>
        </el-form-item>
        <el-form-item label="URL">
          <el-input v-model="form.url" placeholder="Webhook URL" />
        </el-form-item>
        <el-form-item label="Secret">
          <el-input v-model="form.secret" placeholder="签名密钥（可选）" />
        </el-form-item>
        <el-form-item label="启用">
          <el-switch v-model="form.enabled" />
        </el-form-item>
        <el-form-item label="模板" v-if="form.type === 'custom'">
          <el-input v-model="form.template" type="textarea" :rows="4" placeholder="自定义JSON模板，支持变量: {{.URL}}, {{.Title}}, {{.Severity}}, {{.VulnClass}}, {{.Description}}, {{.Time}}" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" @click="saveWebhook">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import api from '../utils/api'
import { ElMessage } from 'element-plus'

const webhooks = ref([])
const loading = ref(false)
const dialogVisible = ref(false)
const isEdit = ref(false)
const form = reactive({
  id: '',
  name: '',
  type: 'dingtalk',
  url: '',
  secret: '',
  enabled: true,
  template: '',
})

const supportedTypes = [
  { type: 'dingtalk', name: '钉钉', desc: '钉钉群机器人', icon: 'ChatDotRound', color: '#409eff' },
  { type: 'wecom', name: '企业微信', desc: '企业微信群机器人', icon: 'ChatLineSquare', color: '#67c23a' },
  { type: 'lark', name: '飞书', desc: '飞书群机器人', icon: 'Message', color: '#e6a23c' },
  { type: 'custom', name: '自定义', desc: '自定义Webhook', icon: 'Setting', color: '#909399' },
]

const typeLabel = (t) => ({ dingtalk: '钉钉', wecom: '企业微信', lark: '飞书', custom: '自定义' }[t] || t)

const fetchWebhooks = async () => {
  loading.value = true
  try {
    const res = await api.get('/webhooks')
    if (res.code === 200) {
      webhooks.value = res.data || []
    }
  } catch {} finally {
    loading.value = false
  }
}

const showAddDialog = () => {
  isEdit.value = false
  Object.assign(form, { id: '', name: '', type: 'dingtalk', url: '', secret: '', enabled: true, template: '' })
  dialogVisible.value = true
}

const editWebhook = (row) => {
  isEdit.value = true
  Object.assign(form, row)
  dialogVisible.value = true
}

const saveWebhook = async () => {
  try {
    const res = await api.post('/webhooks', form)
    if (res.code === 200) {
      ElMessage.success(isEdit.value ? '更新成功' : '添加成功')
      dialogVisible.value = false
      fetchWebhooks()
    } else {
      ElMessage.error(res.message)
    }
  } catch {
    ElMessage.error('保存失败')
  }
}

const deleteWebhook = async (id) => {
  try {
    await api.delete('/webhooks', { params: { id } })
    ElMessage.success('删除成功')
    fetchWebhooks()
  } catch {
    ElMessage.error('删除失败')
  }
}

const testWebhook = async (id) => {
  try {
    const res = await api.post('/webhooks/test', { id })
    if (res.code === 200) {
      ElMessage.success('测试通知已发送')
    }
  } catch {
    ElMessage.error('测试失败')
  }
}

onMounted(fetchWebhooks)
</script>

<style scoped>
.page-title {
  font-size: 22px;
  font-weight: 600;
  margin-bottom: 20px;
  color: #e0e0e0;
}
.type-card {
  text-align: center;
  padding: 20px;
  border-radius: 8px;
  background: #232440;
  border: 1px solid rgba(255,255,255,0.06);
}
.type-name {
  margin-top: 8px;
  font-size: 15px;
  font-weight: 600;
  color: #e0e0e0;
}
.type-desc {
  margin-top: 4px;
  font-size: 12px;
  color: #a0a3bd;
}
</style>
