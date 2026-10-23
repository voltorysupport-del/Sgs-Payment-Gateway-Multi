import { runStagingCli } from '../admin/staging-cli.js';

// Deliberately does not load .env and never connects unless explicit staging
// authorization, configuration, and server-side verification all succeed.
process.exitCode = await runStagingCli(
  process.argv.slice(2),
  process.env,
  (text) => {
    process.stdout.write(text);
  },
  (text) => {
    process.stderr.write(text);
  },
);
