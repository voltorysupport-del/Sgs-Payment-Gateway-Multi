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
          exclude: [
            'tests/integration/dashboard-browser.test.ts',
            'tests/integration/management-browser.test.ts',
            'tests/integration/merchant-browser.test.ts',
            'tests/integration/invitation-browser.test.ts',
            'tests/integration/passkey-ui-browser.test.ts',
            'tests/integration/management-domain.test.ts',
            'tests/integration/management-api.test.ts',
            'tests/integration/merchant-lifecycle.test.ts',
            'tests/integration/merchant-session.test.ts',
            'tests/integration/invitation-acceptance.test.ts',
          ],
        },
      },
      {
        test: {
          ...backend,
          name: 'management',
          sequence: { groupOrder: 1 },
          include: [
            'tests/integration/management-domain.test.ts',
            'tests/integration/management-api.test.ts',
            'tests/integration/merchant-lifecycle.test.ts',
            'tests/integration/merchant-session.test.ts',
            'tests/integration/invitation-acceptance.test.ts',
          ],
          // Owner-policy invalidation intentionally affects every owner fixture.
          // Explicit intra-test barriers exercise concurrency without unrelated
          // fixture issuers racing global invalidation/immutable-audit teardown.
          fileParallelism: false,
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
          fileParallelism: false,
          include: [
            'tests/integration/dashboard-browser.test.ts',
            'tests/integration/management-browser.test.ts',
            'tests/integration/merchant-browser.test.ts',
            'tests/integration/invitation-browser.test.ts',
            'tests/integration/passkey-ui-browser.test.ts',
          ],
          sequence: { groupOrder: 2 },
        },
      },
    ],
  },
});
