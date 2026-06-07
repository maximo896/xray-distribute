import { createRouter, createWebHistory } from 'vue-router'

const routes = [
  {
    path: '/',
    name: 'Dashboard',
    component: () => import('../views/Dashboard.vue'),
  },
  {
    path: '/vulns',
    name: 'Vulnerabilities',
    component: () => import('../views/Vulnerabilities.vue'),
  },
  {
    path: '/agents',
    name: 'Agents',
    component: () => import('../views/Agents.vue'),
  },
  {
    path: '/xray',
    name: 'XRay',
    component: () => import('../views/XRay.vue'),
  },
  {
    path: '/webhooks',
    name: 'Webhooks',
    component: () => import('../views/Webhooks.vue'),
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

export default router
