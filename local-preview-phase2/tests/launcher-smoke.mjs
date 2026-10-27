/* global URL, fetch */
import process from 'node:process';
import { setTimeout, clearTimeout } from 'node:timers';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const cwd = fileURLToPath(new URL('../', import.meta.url));
const windows = process.platform === 'win32';
const child = spawn(
  windows ? 'cmd.exe' : process.execPath,
  windows ? ['/d', '/c', 'Preview-Dashboard.cmd'] : ['scripts/server.mjs'],
  { cwd, shell: false, stdio: ['pipe', 'pipe', 'pipe'] },
);
let output = '';
try {
  await new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error('Local launcher did not start within deadline.')),
      10000,
    );
    child.once('error', (e) => {
      clearTimeout(timer);
      reject(e);
    });
    child.once('exit', () => {
      clearTimeout(timer);
      reject(new Error('Local launcher stopped before ready.'));
    });
    child.stderr.on('data', () => {});
    child.stdout.on('data', (chunk) => {
      output += chunk.toString();
      if (output.includes('http://127.0.0.1:4175/')) {
        clearTimeout(timer);
        resolve();
      }
    });
  });
  const response = await fetch('http://127.0.0.1:4175/');
  assert.equal(response.status, 200);
  assert.match(await response.text(), /SIMULATED/);
  process.stdout.write('PASS: actual local launcher serves synthetic preview on 127.0.0.1 only.');
} finally {
  if (child.pid) {
    if (windows)
      await new Promise((resolve) => {
        const kill = spawn('taskkill.exe', ['/PID', String(child.pid), '/T', '/F'], {
          shell: false,
          stdio: 'ignore',
        });
        kill.once('close', resolve);
        kill.once('error', resolve);
      });
    else child.kill('SIGTERM');
  }
}
