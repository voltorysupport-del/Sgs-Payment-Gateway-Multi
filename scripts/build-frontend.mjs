/* global process */
import { build } from 'vite';

// Portable on Windows CMD too. This build subprocess never inherits test-mode
// React/JSX output; server and test safety flags remain untouched.
process.env.NODE_ENV = 'production';
await build({ configFile: 'frontend/vite.config.ts' });

await build({ configFile: 'frontend/owner.vite.config.ts' });
