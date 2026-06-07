import axios from 'axios'

const api = axios.create({
  baseURL: '/api/v1',
  timeout: 15000,
})

// 请求拦截器 - 添加Token
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('xray-token')
  if (token) {
    config.headers['X-Token'] = token
  }
  return config
})

// 响应拦截器
api.interceptors.response.use(
  (response) => response.data,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('xray-token')
      window.location.reload()
    }
    return Promise.reject(error)
  }
)

export default api
