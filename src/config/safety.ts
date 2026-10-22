/**
 * A second, independent check that real payment processing is switched off.
 *
 * `loadConfig` already rejects unsafe settings. This function is called again
 * when the app is built, so that a mistake in one place (for example, someone
 * constructing a Config object by hand) cannot silently enable real payments.
 */
import { SUPPORTED_PROVIDERS, type Config } from './index.js';

export class UnsafeConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UnsafeConfigurationError';
  }
}

export function assertRealPaymentsDisabled(config: Config): void {
  // The type says this is always `false`; we still check at runtime.
  if ((config.liveModeEnabled as boolean) !== false) {
    throw new UnsafeConfigurationError(
      'Refusing to start: live mode is enabled, but real payments are disabled in Version 1.',
    );
  }

  const unknownProviders = config.allowedProviders.filter(
    (name) => !(SUPPORTED_PROVIDERS as readonly string[]).includes(name),
  );
  if (unknownProviders.length > 0) {
    throw new UnsafeConfigurationError(
      'Refusing to start: only the simulator provider is permitted in Version 1.',
    );
  }

  if (config.nodeEnv === 'production' && config.simulatorControlsEnabled) {
    throw new UnsafeConfigurationError(
      'Refusing to start: simulator controls must be disabled in production.',
    );
  }
}
