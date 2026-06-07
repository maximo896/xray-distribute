<template>
  <div class="vulns-page">
    <h2 class="page-title">漏洞列表</h2>

    <!-- 筛选栏 -->
    <el-card shadow="hover" style="margin-bottom: 20px">
      <el-row :gutter="16" align="middle">
        <el-col :span="6">
          <el-input v-model="keyword" placeholder="搜索URL或标题" clearable @clear="fetchVulns" @keyup.enter="fetchVulns">
            <template #prefix><el-icon><Search /></el-icon></template>
          </el-input>
        </el-col>
        <el-col :span="4">
          <el-select v-model="severity" placeholder="危险等级" clearable @change="fetchVulns">
            <el-option label="高危" value="high" />
            <el-option label="中危" value="medium" />
            <el-option label="低危" value="low" />
            <el-option label="信息" value="info" />
          </el-select>
        </el-col>
        <el-col :span="4">
          <el-button type="primary" @click="fetchVulns">
            <el-icon><Search /></el-icon>搜索
          </el-button>
        </el-col>
      </el-row>
    </el-card>

    <!-- 漏洞表格 -->
    <el-card shadow="hover">
      <el-table :data="vulns" stripe style="width: 100%" v-loading="loading">
        <el-table-column prop="vuln_class" label="漏洞类型" width="160" />
        <el-table-column prop="severity" label="等级" width="80">
          <template #default="{ row }">
            <el-tag :type="severityType(row.severity)" size="small" effect="dark">
              {{ severityLabel(row.severity) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="title" label="漏洞标题" min-width="200" show-overflow-tooltip />
        <el-table-column prop="url" label="目标URL" min-width="280" show-overflow-tooltip>
          <template #default="{ row }">
            <a :href="row.url" target="_blank" class="url-link">{{ row.url }}</a>
          </template>
        </el-table-column>
        <el-table-column prop="created_at" label="发现时间" width="180">
          <template #default="{ row }">
            {{ formatTime(row.created_at) }}
          </template>
        </el-table-column>
        <el-table-column label="操作" width="100" fixed="right">
          <template #default="{ row }">
            <el-button type="primary" link size="small" @click="showDetail(row)">详情</el-button>
          </template>
        </el-table-column>
      </el-table>

      <div class="pagination-wrap">
        <el-pagination
          v-model:current-page="page"
          v-model:page-size="pageSize"
          :total="total"
          :page-sizes="[20, 50, 100]"
          layout="total, sizes, prev, pager, next"
          @size-change="fetchVulns"
          @current-change="fetchVulns"
        />
      </div>
    </el-card>

    <!-- 漏洞详情弹窗 -->
    <el-dialog v-model="detailVisible" title="漏洞详情" width="700px">
      <template v-if="currentVuln">
        <el-descriptions :column="2" border>
          <el-descriptions-item label="漏洞类型">{{ currentVuln.vuln_class }}</el-descriptions-item>
          <el-descriptions-item label="危险等级">
            <el-tag :type="severityType(currentVuln.severity)" effect="dark">
              {{ severityLabel(currentVuln.severity) }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="漏洞标题" :span="2">{{ currentVuln.title }}</el-descriptions-item>
          <el-descriptions-item label="目标URL" :span="2">
            <a :href="currentVuln.url" target="_blank" class="url-link">{{ currentVuln.url }}</a>
          </el-descriptions-item>
          <el-descriptions-item label="描述" :span="2">{{ currentVuln.description || '无' }}</el-descriptions-item>
          <el-descriptions-item label="修复建议" :span="2">{{ currentVuln.solution || '无' }}</el-descriptions-item>
        </el-descriptions>

        <div v-if="currentVuln.request" style="margin-top: 16px">
          <h4 style="color: #a0a3bd; margin-bottom: 8px">请求包</h4>
          <pre class="code-block">{{ currentVuln.request }}</pre>
        </div>

        <div v-if="currentVuln.response" style="margin-top: 16px">
          <h4 style="color: #a0a3bd; margin-bottom: 8px">响应包</h4>
          <pre class="code-block">{{ currentVuln.response }}</pre>
        </div>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import api from '../utils/api'

const vulns = ref([])
const loading = ref(false)
const keyword = ref('')
const severity = ref('')
const page = ref(1)
const pageSize = ref(20)
const total = ref(0)
const detailVisible = ref(false)
const currentVuln = ref(null)

const severityType = (s) => ({ high: 'danger', medium: 'warning', low: 'success', info: 'info' }[s] || 'info')
const severityLabel = (s) => ({ high: '高危', medium: '中危', low: '低危', info: '信息' }[s] || s)

const formatTime = (t) => {
  if (!t) return '-'
  return new Date(t).toLocaleString('zh-CN')
}

const fetchVulns = async () => {
  loading.value = true
  try {
    const res = await api.get('/vulns', {
      params: {
        keyword: keyword.value,
        severity: severity.value,
        page: page.value,
        page_size: pageSize.value,
      },
    })
    if (res.code === 200) {
      vulns.value = res.data.list || []
      total.value = res.data.total || 0
    }
  } catch {} finally {
    loading.value = false
  }
}

const showDetail = (vuln) => {
  currentVuln.value = vuln
  detailVisible.value = true
}

onMounted(fetchVulns)
</script>

<style scoped>
.page-title {
  font-size: 22px;
  font-weight: 600;
  margin-bottom: 20px;
  color: #e0e0e0;
}
.url-link {
  color: #409eff;
  text-decoration: none;
}
.url-link:hover {
  text-decoration: underline;
}
.pagination-wrap {
  margin-top: 16px;
  display: flex;
  justify-content: flex-end;
}
.code-block {
  background: #0f1021;
  border: 1px solid rgba(255,255,255,0.06);
  border-radius: 6px;
  padding: 12px;
  font-size: 12px;
  line-height: 1.6;
  overflow-x: auto;
  color: #c0c4cc;
  max-height: 300px;
  overflow-y: auto;
}
</style>
