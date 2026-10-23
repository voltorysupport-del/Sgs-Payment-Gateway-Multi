import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    // Tests must never depend on a developer's local .env file.
    env: {
      NODE_ENV: 'test',
      LIVE_MODE_ENABLED: 'false',
      ALLOWED_PROVIDERS: 'simulator',
      SIMULATOR_CONTROLS_ENABLED: 'false',
    },
    restoreMocks: true,
  },
});
