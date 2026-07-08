import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:3001',
        changeOrigin: true,
      },
    },
  },
  build: {
    rollupOptions: {
      output: {
        // Split heavy, independently-cacheable vendor libs out of the main bundle
        // so the initial load ships less JS and these chunks cache across deploys.
        manualChunks: {
          'vendor-flow': ['reactflow', 'dagre'],
          'vendor-editor': ['@tiptap/react', '@tiptap/starter-kit', 'tiptap-markdown'],
          'vendor-pdf': ['jspdf'],
          'vendor-markdown': ['react-markdown'],
        },
      },
    },
  },
})
