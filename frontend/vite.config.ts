import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [
    react({
      fastRefresh: false,
    }),
  ],
  server: {
    host: '0.0.0.0',
    port: 3000,
    hmr: false,
    // watch: false,      // ⚠ Vite puede no aceptar false, se puede eliminar
    proxy: {
      '/api': {
        target: 'http://backend:3001',
        changeOrigin: true,
        secure: false,
        ws: false,
      },
    },
  },
});
