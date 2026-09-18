import axios from 'axios';

const api = axios.create({
  baseURL: '/api/v1',
  headers: {
    'Content-Type': 'application/json',
  },
});

axios.interceptors.request.use((config) => {
  console.log(`[API CALL] ${config.url} - ${new Date().toLocaleTimeString()}`);
  return config;
})

// Response interceptor
api.interceptors.response.use(
  (response) => response,
  (error) => {
    console.error('API Error:', error.response?.data || error.message);
    return Promise.reject(error);
  }
);

// Upload API
export const uploadApi = {
  uploadApp: (file: File) => {
    const formData = new FormData();
    formData.append('file', file);
    return api.post('/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
      timeout: 300000,
    });
  },
};

// Analysis API
export const analysisApi = {
  listApps: (params?: { page?: number; page_size?: number; platform?: string; status?: string }) =>
    api.get('/analysis/applications', { params }),
  getApp: (appId: number) =>
    api.get(`/analysis/applications/${appId}`),
  deleteApp: (appId: number) =>
    api.delete(`/analysis/applications/${appId}`),
  getStatistics: () =>
    api.get('/analysis/statistics'),
  runBlutter: (appId: number) =>
    api.post(`/analysis/applications/${appId}/run-blutter`, {}, { timeout: 1800000 }),
  patchReFlutter: (appId: number, body: { burpIp: string; mode?: 'traffic' | 'offset' }) =>
    api.post(`/analysis/applications/${appId}/patch-reflutter`, body, { timeout: 300000 }),
  extractOffset: (appId: number) =>
    api.post(`/analysis/applications/${appId}/extract-offset`, {}, { timeout: 120000 }),
};
export default api;
