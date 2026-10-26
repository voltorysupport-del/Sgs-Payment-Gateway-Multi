import { defineConfig } from 'vitest/config';

const backend = {
  environment: 'node' as const,
  // Tests never inherit live payment settings or depend on a developer .env file.
  env: {
    NODE_ENV: 'test',
    LIVE_MODE_ENABLED: 'false',
    ALLOWED_PROVIDERS: 'simulator',
    SIMULATOR_CONTROLS_ENABLED: 'false',
  },
  restoreMocks: true,
};
export default defineConfig({
  test: {
    projects: [
      {
        test: {
          ...backend,
          name: 'backend',
          include: ['tests/**/*.test.ts'],
          exclude: ['tests/integration/dashboard-browser.test.ts'],
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
      // Existing auth fixtures clean anonymous sessions/limit buckets. Finish them
      // before the browser starts its real CSRF/login sequence in the same test DB.
      {
        test: {
          ...backend,
          name: 'browser',
          include: ['tests/integration/dashboard-browser.test.ts'],
          sequence: { groupOrder: 1 },
        },
      },
    ],
  },
});
