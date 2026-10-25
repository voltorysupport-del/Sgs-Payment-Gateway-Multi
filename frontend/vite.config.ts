import { defineConfig } from 'vite';
import { fileURLToPath } from 'node:url';
export default defineConfig({
  envDir: false,
  root: fileURLToPath(new URL('.', import.meta.url)),
  base: '/dashboard/',
  build: { outDir: '../dist/dashboard-ui', emptyOutDir: true, sourcemap: false },
  server: { host: '127.0.0.1' },
});
