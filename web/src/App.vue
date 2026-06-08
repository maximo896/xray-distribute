<template>
  <el-container class="app-shell">
    <el-aside :width="isCollapse ? '72px' : '232px'" class="sidebar">
      <button class="brand" @click="$router.push('/')">
        <el-icon :size="24"><Monitor /></el-icon>
        <span v-show="!isCollapse">XRay Distribute</span>
      </button>

      <el-menu
        :default-active="$route.path"
        :collapse="isCollapse"
        router
        class="nav"
        background-color="transparent"
        text-color="#9ca3af"
        active-text-color="#f8fafc"
      >
        <el-menu-item index="/">
          <el-icon><DataAnalysis /></el-icon>
          <template #title>总览</template>
        </el-menu-item>
        <el-menu-item index="/vulns">
          <el-icon><Warning /></el-icon>
          <template #title>漏洞</template>
        </el-menu-item>
        <el-menu-item index="/agents">
          <el-icon><Connection /></el-icon>
          <template #title>Agent</template>
        </el-menu-item>
        <el-menu-item index="/xray">
          <el-icon><Cpu /></el-icon>
          <template #title>XRay</template>
        </el-menu-item>
        <el-menu-item index="/webhooks">
          <el-icon><Bell /></el-icon>
          <template #title>通知</template>
        </el-menu-item>
      </el-menu>
    </el-aside>

    <el-container>
      <el-header class="topbar">
        <div class="topbar-left">
          <el-button :icon="isCollapse ? Expand : Fold" circle @click="isCollapse = !isCollapse" />
          <div>
            <div class="page-kicker">Passive Security Scanner</div>
            <div class="page-name">{{ routeName }}</div>
          </div>
        </div>
        <div class="topbar-right">
          <el-tag :type="connected ? 'success' : 'danger'" effect="plain">
            {{ connected ? 'API 已连接' : 'API 未连接' }}
          </el-tag>
        </div>
      </el-header>

      <el-main class="main">
        <router-view />
      </el-main>
    </el-container>

    <el-dialog v-model="showTokenDialog" title="连接 Token" width="420px" :close-on-click-modal="false" :show-close="false">
      <el-input v-model="token" placeholder="输入 server.token" type="password" show-password @keyup.enter="saveToken" />
      <template #footer>
        <el-button type="primary" @click="saveToken">连接</el-button>
      </template>
    </el-dialog>
  </el-container>
</template>

<script setup>
import { computed, ref, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { Expand, Fold } from '@element-plus/icons-vue'
import api from './utils/api'

const route = useRoute()
const isCollapse = ref(false)
const connected = ref(false)
const showTokenDialog = ref(false)
const token = ref('')

const names = {
  '/': '扫描总览',
  '/vulns': '漏洞列表',
  '/agents': 'Agent 节点',
  '/xray': 'XRay 引擎',
  '/webhooks': 'Webhook 通知',
}

const routeName = computed(() => names[route.path] || '控制台')

const checkConnection = async () => {
  const savedToken = localStorage.getItem('xray-token')
  if (!savedToken) {
    connected.value = false
    showTokenDialog.value = true
    return
  }
  try {
    await api.get('/ping')
    connected.value = true
  } catch {
    connected.value = false
    showTokenDialog.value = true
  }
}

const saveToken = () => {
  if (!token.value) return
  localStorage.setItem('xray-token', token.value)
  showTokenDialog.value = false
  checkConnection()
}

onMounted(() => {
  token.value = localStorage.getItem('xray-token') || ''
  checkConnection()
  setInterval(checkConnection, 30000)
})
</script>

<style>
* {
  box-sizing: border-box;
}

body {
  margin: 0;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  color: #e5e7eb;
  background: #101214;
}

.app-shell {
  height: 100vh;
}

.sidebar {
  background: #171a1f;
  border-right: 1px solid #2a2f36;
  overflow: hidden;
}

.brand {
  width: 100%;
  height: 64px;
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 0 20px;
  color: #f8fafc;
  background: transparent;
  border: 0;
  border-bottom: 1px solid #2a2f36;
  cursor: pointer;
  font-weight: 700;
}

.nav {
  border-right: 0 !important;
  padding: 10px 8px;
}

.nav .el-menu-item {
  height: 42px;
  border-radius: 8px;
  margin: 4px 0;
}

.nav .el-menu-item.is-active {
  background: #243241 !important;
}

.topbar {
  height: 64px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 24px;
  background: #14171b;
  border-bottom: 1px solid #2a2f36;
}

.topbar-left,
.topbar-right {
  display: flex;
  align-items: center;
  gap: 14px;
}

.page-kicker {
  color: #8b949e;
  font-size: 12px;
  line-height: 18px;
}

.page-name {
  color: #f8fafc;
  font-size: 18px;
  font-weight: 700;
}

.main {
  background: #101214;
  padding: 24px;
  overflow: auto;
}

.panel {
  background: #171a1f;
  border: 1px solid #2a2f36;
  border-radius: 8px;
}

.panel-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 16px 18px;
  border-bottom: 1px solid #2a2f36;
}

.panel-title {
  color: #f8fafc;
  font-size: 15px;
  font-weight: 700;
}

.muted {
  color: #8b949e;
}

.el-card {
  --el-card-bg-color: #171a1f;
  --el-card-border-color: #2a2f36;
  color: #e5e7eb;
  border-radius: 8px;
}

.el-table {
  --el-table-bg-color: #171a1f;
  --el-table-tr-bg-color: #171a1f;
  --el-table-header-bg-color: #1d2229;
  --el-table-row-hover-bg-color: #20262d;
  --el-table-border-color: #2a2f36;
  --el-table-text-color: #d1d5db;
  --el-table-header-text-color: #f8fafc;
}

.el-dialog {
  --el-dialog-bg-color: #171a1f;
}

.el-dialog__title,
.el-form-item__label {
  color: #e5e7eb;
}

.el-input__wrapper {
  background: #101214 !important;
  box-shadow: 0 0 0 1px #2a2f36 inset !important;
}

.el-input__inner {
  color: #f8fafc !important;
}
</style>
