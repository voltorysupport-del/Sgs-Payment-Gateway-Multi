/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS tooling. */
/* global module */
const reasons = new Map([
  ...['configuration', 'target', 'operator', 'key', 'delivery'].map((name) => [
    `Staging provisioning refused (${name}). See docs/staging-provisioning.md.`,
    name.toUpperCase(),
  ]),
  [
    'Staging provisioning failed. No error details are logged. Check status before retrying.',
    'DATABASE_OR_INTERNAL_FAILURE',
  ],
]);
function cliReason(text) {
  return reasons.get(typeof text === 'string' ? text.trim() : '') || 'UNCLASSIFIED_CLI_FAILURE';
}
const extraReasons = [
  'WORKER_NOT_READY_BEFORE_CLI',
  'CLI_EXCEPTION',
  'CONFIRMATION_CANCELLED',
  'POST_CLI_VERIFICATION_FAILED',
];
const phases = new Set([
  'WORKER_START',
  'CONFIG_VALIDATED',
  'ORIGINAL_EVIDENCE_VALIDATED',
  'READ_ONLY_CHECKED',
  'CONFIRMED',
  'RECOVERY_RECORDED',
  'CLI_CALL_STARTED',
  'CLI_RETURNED_FAILURE',
  'CLI_RETURNED_SUCCESS',
  'METADATA_VERIFIED',
  'RECEIPT_WRITTEN',
]);
function publicOutcome({ phase, attempted, cliStatus, reason, result }) {
  return {
    result:
      result === 'RECOVERY_VERIFIED' &&
      phase === 'RECEIPT_WRITTEN' &&
      attempted === true &&
      cliStatus === 0
        ? 'RECOVERY_VERIFIED'
        : attempted !== false
          ? 'STOP_RECOVERY_OUTCOME_UNVERIFIED'
          : 'STOP_BEFORE_RECOVERY_INVOCATION',
    phase: phases.has(phase) ? phase : 'UNKNOWN',
    attempted: typeof attempted === 'boolean' ? attempted : null,
    ...(cliStatus === 0 || cliStatus === 1 ? { cliStatus } : {}),
    ...(Array.from(reasons.values()).includes(reason) ||
    extraReasons.includes(reason) ||
    reason === 'UNCLASSIFIED_CLI_FAILURE'
      ? { reason }
      : {}),
    retryAllowed: false,
  };
}
module.exports = { cliReason, publicOutcome };
