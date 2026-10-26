import { defineConfig } from 'vite';
import { fileURLToPath } from 'node:url';
export default defineConfig({
  envDir: false,
  root: fileURLToPath(new URL('.', import.meta.url)),
  base: '/owner/',
  build: {
    outDir: '../dist/owner-ui',
    emptyOutDir: true,
    sourcemap: false,
    rollupOptions: { input: fileURLToPath(new URL('owner.html', import.meta.url)) },
  },
  server: { host: '127.0.0.1' },
});
