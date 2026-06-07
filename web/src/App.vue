<template>
  <el-container class="app-container">
    <!-- 侧边栏 -->
    <el-aside :width="isCollapse ? '64px' : '220px'" class="app-aside">
      <div class="logo" @click="$router.push('/')">
        <el-icon :size="28"><Monitor /></el-icon>
        <span v-show="!isCollapse" class="logo-text">XRay Distribute</span>
      </div>
      <el-menu
        :default-active="$route.path"
        :collapse="isCollapse"
        router
        class="app-menu"
        background-color="#1d1e2c"
        text-color="#a0a3bd"
        active-text-color="#409eff"
      >
        <el-menu-item index="/">
          <el-icon><DataAnalysis /></el-icon>
          <template #title>仪表盘</template>
        </el-menu-item>
        <el-menu-item index="/vulns">
          <el-icon><Warning /></el-icon>
          <template #title>漏洞列表</template>
        </el-menu-item>
        <el-menu-item index="/agents">
          <el-icon><Connection /></el-icon>
          <template #title>Agent节点</template>
        </el-menu-item>
        <el-menu-item index="/xray">
          <el-icon><Cpu /></el-icon>
          <template #title>XRay管理</template>
        </el-menu-item>
        <el-menu-item index="/webhooks">
          <el-icon><Bell /></el-icon>
          <template #title>Webhook通知</template>
        </el-menu-item>
      </el-menu>
    </el-aside>

    <!-- 主内容区 -->
    <el-container>
      <el-header class="app-header">
        <div class="header-left">
          <el-icon class="collapse-btn" @click="isCollapse = !isCollapse">
            <Fold v-if="!isCollapse" />
            <Expand v-else />
          </el-icon>
        </div>
        <div class="header-right">
          <el-tag :type="connected ? 'success' : 'danger'" effect="dark" size="small">
            {{ connected ? '已连接' : '未连接' }}
          </el-tag>
        </div>
      </el-header>
      <el-main class="app-main">
        <router-view />
      </el-main>
    </el-container>

    <!-- Token设置弹窗 -->
    <el-dialog v-model="showTokenDialog" title="设置连接Token" width="400px" :close-on-click-modal="false" :show-close="false">
      <el-input v-model="token" placeholder="请输入Server的Token" type="password" show-password />
      <template #footer>
        <el-button type="primary" @click="saveToken">连接</el-button>
      </template>
    </el-dialog>
  </el-container>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import api from './utils/api'

const isCollapse = ref(false)
const connected = ref(false)
const showTokenDialog = ref(false)
const token = ref('')

const checkConnection = async () => {
  try {
    await api.get('/ping')
    connected.value = true
  } catch {
    connected.value = false
    if (!localStorage.getItem('xray-token')) {
      showTokenDialog.value = true
    }
  }
}

const saveToken = () => {
  if (token.value) {
    localStorage.setItem('xray-token', token.value)
    showTokenDialog.value = false
    checkConnection()
  }
}

onMounted(() => {
  token.value = localStorage.getItem('xray-token') || ''
  checkConnection()
  setInterval(checkConnection, 30000)
})
</script>

<style>
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
  background: #0f1021;
  color: #e0e0e0;
}

.app-container {
  height: 100vh;
}

.app-aside {
  background: #1d1e2c;
  transition: width 0.3s;
  overflow: hidden;
}

.logo {
  height: 60px;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  cursor: pointer;
  border-bottom: 1px solid rgba(255,255,255,0.06);
  color: #409eff;
}

.logo-text {
  font-size: 16px;
  font-weight: 700;
  white-space: nowrap;
  background: linear-gradient(135deg, #409eff, #79bbff);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}

.app-menu {
  border-right: none;
}

.app-header {
  background: #1a1b2e;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 20px;
  border-bottom: 1px solid rgba(255,255,255,0.06);
}

.collapse-btn {
  cursor: pointer;
  font-size: 20px;
  color: #a0a3bd;
  transition: color 0.2s;
}

.collapse-btn:hover {
  color: #409eff;
}

.app-main {
  background: #0f1021;
  padding: 20px;
  overflow-y: auto;
}

/* 自定义滚动条 */
::-webkit-scrollbar {
  width: 6px;
}
::-webkit-scrollbar-track {
  background: transparent;
}
::-webkit-scrollbar-thumb {
  background: rgba(255,255,255,0.1);
  border-radius: 3px;
}

/* Element Plus 暗色覆盖 */
.el-card {
  background: #1a1b2e !important;
  border-color: rgba(255,255,255,0.06) !important;
  color: #e0e0e0 !important;
}
.el-card__header {
  border-color: rgba(255,255,255,0.06) !important;
  color: #e0e0e0 !important;
}
.el-table {
  background: #1a1b2e !important;
  --el-table-bg-color: #1a1b2e;
  --el-table-tr-bg-color: #1a1b2e;
  --el-table-header-bg-color: #232440;
  --el-table-row-hover-bg-color: #232440;
  --el-table-border-color: rgba(255,255,255,0.06);
  --el-table-text-color: #c0c4cc;
  --el-table-header-text-color: #e0e0e0;
}
.el-dialog {
  background: #1a1b2e !important;
}
.el-dialog__title {
  color: #e0e0e0 !important;
}
.el-form-item__label {
  color: #a0a3bd !important;
}
.el-input__wrapper {
  background: #232440 !important;
}
.el-input__inner {
  color: #e0e0e0 !important;
}
.el-pagination {
  --el-pagination-bg-color: #1a1b2e;
  --el-pagination-text-color: #a0a3bd;
  --el-pagination-button-bg-color: #232440;
}
</style>
