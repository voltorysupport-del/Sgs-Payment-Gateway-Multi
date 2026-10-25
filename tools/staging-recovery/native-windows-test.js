/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS tooling. */
/* global require, process, __filename, setTimeout, clearTimeout */
// Credential-free Windows process/IPC boundary regression. No DB or real CLI.
const { fork } = require('node:child_process'),
  fs = require('node:fs'),
  os = require('node:os'),
  path = require('node:path'),
  assert = require('node:assert/strict');
if (process.argv[2] === 'child') {
  let called = false;
  process.once('message', (message) => {
    if (message?.action === 'disconnect-before-cli') {
      process.disconnect();
      return;
    }
    if (message?.action === 'confirm') {
      if (!process.connected) throw Error();
      called = true;
      process.send({ phase: 'CLI_CALL_STARTED', attempted: called }, () => process.disconnect());
    }
  });
  process.send({ phase: 'RECOVERY_RECORDED' });
} else if (process.platform !== 'win32')
  process.stdout.write('SKIPPED: native Windows IPC checks require Windows.\n');
else
  (async () => {
    const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'vaultx-recovery-ipc-'));
    try {
      const fixture = path.join(temporary, 'Node IPC & Spaces.js');
      fs.copyFileSync(__filename, fixture);
      for (const mode of ['confirm', 'disconnect-before-cli']) {
        let invoked = false,
          recorded = false;
        await new Promise((resolve, reject) => {
          const child = fork(fixture, ['child'], {
            execArgv: [],
            stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
          });
          const timer = setTimeout(() => {
            child.kill();
            reject(Error());
          }, 10000);
          child.on('message', (message) => {
            if (message.phase === 'RECOVERY_RECORDED') {
              recorded = true;
              child.send({ action: mode });
            }
            if (message.phase === 'CLI_CALL_STARTED') invoked = true;
          });
          child.once('error', reject);
          child.once('close', () => {
            clearTimeout(timer);
            resolve();
          });
        });
        assert.ok(recorded);
        assert.equal(invoked, mode === 'confirm');
      }
      process.stdout.write('2 native Windows IPC boundary cases passed; synthetic events only.\n');
    } finally {
      fs.rmSync(temporary, { recursive: true, force: true });
    }
  })().catch(() => {
    process.stderr.write('Native IPC tests failed; details suppressed.\n');
    process.exitCode = 1;
  });
