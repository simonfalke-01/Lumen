import { realpathSync } from 'node:fs'
import { resolve } from 'node:path'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'
import { devApi } from './web/dev/dev-api'

// CMake passes the install assets directory; a plain `npm run build` writes to build/.
const assetsDirectory = process.env.LUMEN_ASSETS_DIR
  ? resolve(realpathSync(process.env.LUMEN_ASSETS_DIR), 'assets/web')
  : resolve('build/assets/web')

export default defineConfig(({ command }) => ({
  root: 'web',
  base: '/',
  plugins: [react(), ...(command === 'serve' ? [devApi()] : [])],
  build: {
    outDir: assetsDirectory,
    emptyOutDir: true,
  },
}))
