import { useEffect, useRef, useState } from 'react';
import type { DashboardAuth, AuthState } from './auth';
import { passkeysSupported } from './passkeys';

export function PasskeyGate({
  controller,
  state,
}: {
  controller: DashboardAuth;
  state: AuthState;
}) {
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => heading.current?.focus(), [state.phase]);
  const pending = state.phase === 'passkey' || state.phase === 'enrollment';
  return (
    <main className="passkey-shell">
      <section className="passkey-card" aria-busy={pending}>
        <span className="mode">SIMULATOR ONLY</span>
        <h1 ref={heading} tabIndex={-1}>
          {state.phase === 'enrollment'
            ? 'Enrolling your passkey'
            : pending
              ? 'Verify your passkey'
              : 'Passkey verification required'}
        </h1>
        <p role="status">
          {state.phase === 'enrollment'
            ? 'Complete the browser prompt. Enrollment does not sign you in or authorize dashboard access.'
            : pending
              ? 'Complete the browser prompt. Wait for server confirmation; do not submit another request.'
              : 'Your password authenticated your identity. Privileged access remains closed until the server verifies your passkey.'}
        </p>
        {state.error && (
          <p role="alert" className="alert">
            {state.error}
          </p>
        )}
        {!passkeysSupported() && (
          <p role="alert">
            A supported browser on a secure HTTPS connection is required. No bypass or recovery is
            available.
          </p>
        )}
        {pending ? (
          <button onClick={controller.cancelPrompt}>Cancel browser prompt</button>
        ) : (
          <>
            {!state.identity?.authentication.passkeysEnabled && (
              <p role="alert">
                Passkey verification is disabled for this environment. Contact your administrator.
              </p>
            )}
            {state.needsRestart && (
              <p>
                Sign out and sign in again to start a fresh verification. The cancelled challenge is
                never reused.
              </p>
            )}
            <button
              className="primary"
              disabled={
                !passkeysSupported() ||
                !state.identity?.authentication.passkeysEnabled ||
                state.needsRestart
              }
              onClick={() => void controller.verifyPasskey()}
            >
              Verify passkey
            </button>
            <button onClick={() => void controller.logout()}>Sign out</button>
          </>
        )}
        <p className="muted">
          Cancelling closes an open browser prompt. A verification already submitted must settle
          before another session change.
        </p>
      </section>
    </main>
  );
}
export function InvitationAcceptance({
  controller,
  onClose,
}: {
  controller: DashboardAuth;
  onClose: () => void;
}) {
  const [error, setError] = useState(''),
    heading = useRef<HTMLHeadingElement>(null),
    form = useRef<HTMLFormElement>(null);
  useEffect(() => {
    heading.current?.focus();
    const clear = () => form.current?.reset();
    document.addEventListener('visibilitychange', clear);
    window.addEventListener('pagehide', clear);
    return () => {
      clear();
      document.removeEventListener('visibilitychange', clear);
      window.removeEventListener('pagehide', clear);
    };
  }, []);
  return (
    <main className="passkey-shell">
      <section className="passkey-card">
        <span className="mode">SYNTHETIC / LOCAL TEST ONLY</span>
        <h1 ref={heading} tabIndex={-1}>
          Accept an invitation
        </h1>
        <p>
          Use an authorized synthetic invitation. No email delivery, recovery or production
          enrollment is available.
        </p>
        <form
          ref={form}
          aria-label="Invitation acceptance"
          method="post"
          action="/dashboard-api/auth/passkeys/enrollment/options"
          onSubmit={(event) => {
            event.preventDefault();
            const data = new FormData(event.currentTarget),
              token = data.get('invitation'),
              password = data.get('password'),
              confirm = data.get('confirm');
            event.currentTarget.reset();
            if (typeof token !== 'string' || typeof password !== 'string' || password !== confirm) {
              setError('Passwords must match. Enter the invitation and passwords again.');
              return;
            }
            if (!/^[a-f0-9]{64}$/.test(token)) {
              setError('Enter a valid invitation value.');
              return;
            }
            void controller.enroll(token, password);
          }}
        >
          <label htmlFor="invitation">Private invitation value</label>
          <input
            id="invitation"
            name="invitation"
            type="password"
            autoComplete="off"
            spellCheck={false}
            autoCapitalize="none"
            required
            minLength={64}
            maxLength={64}
            pattern="[a-f0-9]{64}"
            aria-describedby="invitation-help"
          />
          <p id="invitation-help" className="muted">
            Paste it here, never into an address bar, message or screenshot.
          </p>
          <label htmlFor="enroll-password">Create password</label>
          <input
            id="enroll-password"
            name="password"
            type="password"
            autoComplete="new-password"
            required
            minLength={15}
            maxLength={128}
          />
          <label htmlFor="enroll-confirm">Confirm password</label>
          <input
            id="enroll-confirm"
            name="confirm"
            type="password"
            autoComplete="new-password"
            required
            minLength={15}
            maxLength={128}
          />
          {error && (
            <p role="alert" className="alert">
              {error}
            </p>
          )}
          {!passkeysSupported() && (
            <p role="alert">
              This browser or connection does not support secure passkeys. Use a supported HTTPS
              browser; there is no bypass.
            </p>
          )}
          <button className="primary" disabled={!passkeysSupported()}>
            Enroll passkey
          </button>
        </form>
        <button onClick={onClose}>Back to sign in</button>
      </section>
    </main>
  );
}
