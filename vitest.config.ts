import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    // Tests must never depend on a developer's local .env file.
    env: { NODE_ENV: 'test' },
    restoreMocks: true,
  },
});
