import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      // Any request starting with /api will be forwarded to your Flask backend
      '/api': {
        target: 'https://tsmbackend-production.up.railway.app', // 👈 your Flask backend URL
        changeOrigin: true,
        secure: false,
      },
    },
  },
})
