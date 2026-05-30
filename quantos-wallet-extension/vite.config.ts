import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react-swc'
import { resolve } from 'path'
import { copyFileSync, mkdirSync, existsSync, readdirSync } from 'fs'

function copyStaticFiles() {
  return {
    name: 'copy-extension-files',
    writeBundle() {
      // Copy manifest.json
      copyFileSync(
        resolve(__dirname, 'manifest.json'),
        resolve(__dirname, 'dist/manifest.json')
      )
      // Copy icons if they exist
      const iconsDir = resolve(__dirname, 'public/icons')
      const outIcons = resolve(__dirname, 'dist/icons')
      if (existsSync(iconsDir)) {
        if (!existsSync(outIcons)) mkdirSync(outIcons, { recursive: true })
        for (const file of readdirSync(iconsDir)) {
          copyFileSync(resolve(iconsDir, file), resolve(outIcons, file))
        }
      }
    },
  }
}

export default defineConfig({
  plugins: [react(), copyStaticFiles()],
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        popup: resolve(__dirname, 'popup.html'),
        background: resolve(__dirname, 'src/background/service-worker.ts'),
        content: resolve(__dirname, 'src/content/content.ts'),
        inpage: resolve(__dirname, 'src/content/inpage.ts'),
      },
      output: {
        entryFileNames: (chunk) => {
          if (chunk.name === 'background') return 'background.js'
          if (chunk.name === 'content') return 'content.js'
          if (chunk.name === 'inpage') return 'inpage.js'
          return 'assets/[name]-[hash].js'
        },
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash].[ext]',
      },
    },
  },
})
