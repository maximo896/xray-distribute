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
        text-color="#5f6b7a"
        active-text-color="#1f6feb"
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
  color: #18202a;
  background: #f5f7fb;
  --app-bg: #f5f7fb;
  --app-surface: #ffffff;
  --app-surface-soft: #f9fbfe;
  --app-border: #d9e0ea;
  --app-border-soft: #e7ecf3;
  --app-text: #18202a;
  --app-muted: #667085;
  --app-primary: #1f6feb;
  --app-primary-soft: #eaf2ff;
  --app-danger: #d92d20;
  --app-danger-soft: #fff1f0;
  --app-success: #198754;
  --app-success-soft: #eaf7ef;
  --app-warning: #b7791f;
  --app-code-bg: #f1f5f9;
}

.app-shell {
  height: 100vh;
}

.sidebar {
  background: #ffffff;
  border-right: 1px solid var(--app-border);
  overflow: hidden;
}

.brand {
  width: 100%;
  height: 64px;
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 0 20px;
  color: #18202a;
  background: transparent;
  border: 0;
  border-bottom: 1px solid var(--app-border);
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
  background: var(--app-primary-soft) !important;
}

.topbar {
  height: 64px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 24px;
  background: #ffffff;
  border-bottom: 1px solid var(--app-border);
}

.topbar-left,
.topbar-right {
  display: flex;
  align-items: center;
  gap: 14px;
}

.page-kicker {
  color: var(--app-muted);
  font-size: 12px;
  line-height: 18px;
}

.page-name {
  color: var(--app-text);
  font-size: 18px;
  font-weight: 700;
}

.main {
  background: var(--app-bg);
  padding: 24px;
  overflow: auto;
}

.panel {
  background: var(--app-surface);
  border: 1px solid var(--app-border);
  border-radius: 8px;
  box-shadow: 0 1px 2px rgba(16, 24, 40, .04);
}

.panel-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 16px 18px;
  border-bottom: 1px solid var(--app-border-soft);
}

.panel-title {
  color: var(--app-text);
  font-size: 15px;
  font-weight: 700;
}

.muted {
  color: var(--app-muted);
}

.el-card {
  --el-card-bg-color: #ffffff;
  --el-card-border-color: var(--app-border);
  color: var(--app-text);
  border-radius: 8px;
}

.el-table {
  --el-table-bg-color: #ffffff;
  --el-table-tr-bg-color: #ffffff;
  --el-table-header-bg-color: #f3f6fa;
  --el-table-row-hover-bg-color: #f7faff;
  --el-table-border-color: var(--app-border-soft);
  --el-table-text-color: var(--app-text);
  --el-table-header-text-color: #344054;
}

.el-dialog {
  --el-dialog-bg-color: #ffffff;
}

.el-dialog__title,
.el-form-item__label {
  color: var(--app-text);
}

.el-input__wrapper {
  background: #ffffff !important;
  box-shadow: 0 0 0 1px var(--app-border) inset !important;
}

.el-input__inner {
  color: var(--app-text) !important;
}

.el-select__wrapper,
.el-textarea__inner,
.el-input-number .el-input__wrapper {
  background: #ffffff !important;
  box-shadow: 0 0 0 1px var(--app-border) inset !important;
}

.el-textarea__inner {
  color: var(--app-text) !important;
}

.el-menu {
  --el-menu-hover-bg-color: #f3f6fb;
}

.el-button {
  --el-button-bg-color: #ffffff;
  --el-button-border-color: var(--app-border);
}

.el-pagination {
  --el-pagination-bg-color: #ffffff;
  --el-pagination-button-bg-color: #ffffff;
  --el-pagination-text-color: var(--app-muted);
}
</style>
