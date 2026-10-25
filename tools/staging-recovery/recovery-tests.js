/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS tooling. */
/* global require, process, Buffer */
const fs = require('node:fs'),
  os = require('node:os'),
  path = require('node:path'),
  crypto = require('node:crypto'),
  assert = require('node:assert/strict');
const { recoverOnce, PHRASE } = require(
  require('node:path').join(process.argv[2], 'recovery-controller.js'),
);
const { cliReason, publicOutcome } = require(
  require('node:path').join(process.argv[2], 'diagnostics.js'),
);
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vaultx-recovery-draft-tests-'));
(async () => {
  try {
    for (const mode of [
      'success',
      'concurrent',
      'cancel',
      'database-changed',
      'before-cli-error',
      'ipc-after-record',
      'cli-throws',
      'cli-delivery-error',
      'cli-generic-error',
      'postcheck-error',
      'post-commit-ambiguity',
      'original-changed',
      'wrong-fingerprint',
    ]) {
      const dir = path.join(root, mode);
      fs.mkdirSync(dir);
      const destination = path.join(dir, 'initial.vaultx-key.json');
      const old = Buffer.from(
        JSON.stringify({
          result: 'ATTEMPT_STARTED_DO_NOT_RETRY',
          operatorCode: 'staging-e2e',
          database: 'vaultx_pay_staging',
          applicationCommit: '245752b6722a1a1d0f21d3a21a86564f29da25a2',
          startedAt: '2026-10-25T15:08:36.036Z',
        }),
      );
      fs.writeFileSync(destination + '.issuance-attempt.json', old);
      const approvedOriginalHash = crypto.createHash('sha256').update(old).digest('hex');
      let calls = 0,
        checks = 0;
      const metadata = {
        action: 'issued',
        operatorCode: 'staging-e2e',
        operatorId: '00000000-0000-4000-8000-000000000001',
        keyId: '00000000-0000-4000-8000-000000000002',
        keys: [{ keyId: '00000000-0000-4000-8000-000000000002', revokedAt: null }],
      };
      const options = {
        destination,
        approvedOriginalHash: mode === 'wrong-fingerprint' ? '0'.repeat(64) : approvedOriginalHash,
        readOnlyCheck: async () => {
          checks++;
          if (mode === 'before-cli-error') throw Error();
          return {
            identityVerified: true,
            tlsVerified: true,
            operatorAbsent: mode !== 'database-changed' || checks === 1,
            keysAbsent: true,
            possibleIssuanceSessions: 0,
          };
        },
        confirm: async () => {
          if (mode === 'original-changed')
            fs.appendFileSync(destination + '.issuance-attempt.json', ' ');
          return mode === 'cancel' ? '' : PHRASE;
        },
        beforeCli: async () => {
          if (mode === 'ipc-after-record') throw Error();
        },
        invokePinnedCli: async (args) => {
          calls++;
          assert.equal(args[0], 'ensure');
          if (mode === 'cli-throws') throw Error();
          return {
            status: mode.includes('cli-') ? 1 : 0,
            reason: cliReason(
              mode === 'cli-delivery-error'
                ? 'Staging provisioning refused (delivery). See docs/staging-provisioning.md.'
                : 'Staging provisioning failed. No error details are logged. Check status before retrying.',
            ),
            metadata,
          };
        },
        verifyIssued: async () => !['postcheck-error', 'post-commit-ambiguity'].includes(mode),
      };
      const outcomes =
        mode === 'concurrent'
          ? await Promise.all([recoverOnce(options), recoverOnce(options)])
          : [await recoverOnce(options)];
      const result = outcomes.find((r) => r.result === 'RECOVERY_VERIFIED') || outcomes[0];
      if (mode === 'concurrent')
        assert.equal(outcomes.filter((r) => r.result === 'RECOVERY_VERIFIED').length, 1);
      assert.equal(
        calls,
        [
          'success',
          'concurrent',
          'cli-throws',
          'cli-delivery-error',
          'cli-generic-error',
          'postcheck-error',
          'post-commit-ambiguity',
        ].includes(mode)
          ? 1
          : 0,
      );
      if (mode === 'success' || mode === 'concurrent')
        assert.equal(result.result, 'RECOVERY_VERIFIED');
      if (mode !== 'original-changed')
        assert.ok(fs.readFileSync(destination + '.issuance-attempt.json').equals(old));
      if (mode === 'ipc-after-record') {
        assert.equal(result.attempted, false);
        assert.equal(result.phase, 'RECOVERY_RECORDED');
        assert.equal(result.reason, 'WORKER_NOT_READY_BEFORE_CLI');
      }
      if (mode === 'cli-delivery-error') {
        assert.equal(result.phase, 'CLI_RETURNED_FAILURE');
        assert.equal(result.reason, 'DELIVERY');
      }
      if (mode === 'post-commit-ambiguity') assert.equal(result.phase, 'CLI_RETURNED_SUCCESS');
      if (calls || mode === 'ipc-after-record') {
        await recoverOnce(options);
        assert.equal(calls, mode === 'ipc-after-record' ? 0 : 1);
      }
      process.stdout.write(
        `${mode}: phase=${result.phase}; attempted=${result.attempted}; original preservation/tamper guard and call count verified\n`,
      );
    }
    assert.equal(cliReason('SYNTHETIC-SENSITIVE-ERROR'), 'UNCLASSIFIED_CLI_FAILURE');
    const safe = publicOutcome({
      phase: 'SYNTHETIC-SENSITIVE',
      attempted: false,
      reason: 'SYNTHETIC-SENSITIVE',
    });
    assert.ok(!JSON.stringify(safe).includes('SYNTHETIC'));
    assert.equal(safe.attempted, false);
    process.stdout.write(
      '15 recovery controller/diagnostic checks passed; no DB, real CLI, DPAPI or real files used.\n',
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
})().catch(() => {
  process.stderr.write('Draft tests failed; details suppressed.\n');
  process.exitCode = 1;
});
