import { defineConfig } from 'vitest/config';
export default defineConfig({
  test: {
    projects: [
      {
        test: {
          name: 'backend',
          environment: 'node',
          include: ['tests/**/*.test.ts'],
          env: {
            NODE_ENV: 'test',
            LIVE_MODE_ENABLED: 'false',
            ALLOWED_PROVIDERS: 'simulator',
            SIMULATOR_CONTROLS_ENABLED: 'false',
          },
          restoreMocks: true,
        },
      },
      {
        test: {
          name: 'frontend',
          environment: 'jsdom',
          include: ['frontend/tests/**/*.test.tsx'],
          restoreMocks: true,
        },
      },
    ],
  },
});
