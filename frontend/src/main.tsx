import { useProtectedRead } from './use-protected-read';
import React, { useCallback, useEffect, useState, useSyncExternalStore } from 'react';
import { createRoot } from 'react-dom/client';
import { api, ApiError, type Payment } from './api';
import './styles.css';
import { DashboardAuth } from './auth';
import { PasskeyGate, InvitationAcceptance } from './passkey-ui';

type View = 'overview' | 'payments' | 'status' | `payments/${string}`;
const route = (): View => {
  const value = location.hash.slice(2);
  return value === 'payments' || value === 'status' || /^payments\/[a-f0-9-]+$/i.test(value)
    ? (value as View)
    : 'overview';
};
const field = (data: FormData, name: string): string => {
  const value = data.get(name);
  return typeof value === 'string' ? value : '';
};
export const money = (p: Payment) => {
  // The API stores integer minor units. Do not assume every currency has two decimals.
  if (
    typeof Intl.supportedValuesOf !== 'function' ||
    !Intl.supportedValuesOf('currency').includes(p.currency)
  )
    return `${p.amountMinor} minor units · ${p.currency}`;
  const formatter = new Intl.NumberFormat(undefined, { style: 'currency', currency: p.currency });
  const digits = formatter.resolvedOptions().maximumFractionDigits ?? 2;
  return formatter.format(p.amountMinor / 10 ** digits);
};
const date = (value: string) =>
  new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
function Badge({ status }: { status: Payment['status'] }) {
  return (
    <span className={`badge ${status}`}>
      <span aria-hidden="true">●</span> {status}
    </span>
  );
}
function Alert({ children }: { children: React.ReactNode }) {
  return (
    <div className="alert" role="alert">
      {children}
    </div>
  );
}
function Loading() {
  return (
    <div className="loading" role="status">
      <span className="spinner" /> Loading your workspace…
    </div>
  );
}
function Table({ payments }: { payments: Payment[] }) {
  return payments.length ? (
    <div className="table-wrap" role="region" aria-label="Simulated payment history" tabIndex={0}>
      <table>
        <caption className="sr-only">
          Simulated payments on this page. Scroll horizontally to see all columns.
        </caption>
        <thead>
          <tr>
            <th>Transaction</th>
            <th>Amount</th>
            <th>Status</th>
            <th>Provider</th>
            <th>Created</th>
            <th>
              <span className="sr-only">Actions</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {payments.map((p) => (
            <tr key={p.id}>
              <td>
                <span className="payment-icon" aria-hidden="true">
                  →
                </span>
                <a
                  className="mono"
                  href={`#/payments/${p.id}`}
                  aria-label={`${p.id.slice(0, 8)}…${p.id.slice(-4)} — Open payment ${p.id}`}
                >
                  {p.id.slice(0, 8)}
                  <span className="muted">…{p.id.slice(-4)}</span>
                </a>
              </td>
              <td className="amount">{money(p)}</td>
              <td>
                <Badge status={p.status} />
              </td>
              <td>
                <span className="muted">Simulator</span>
              </td>
              <td className="muted">
                <time dateTime={p.createdAt}>{date(p.createdAt)}</time>
              </td>
              <td>
                <a
                  className="detail-link"
                  href={`#/payments/${p.id}`}
                  aria-label={`View details → for payment ${p.id}`}
                >
                  View details →
                </a>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  ) : (
    <div className="empty" role="status">
      <span aria-hidden="true">◇</span>
      <h3>No payments to show</h3>
      <p>Payments matching these filters will appear here.</p>
    </div>
  );
}
function Login({
  onLogin,
  error,
  onEnroll,
  message,
}: {
  onEnroll: () => void;
  message?: string;
  onLogin: (username: string, password: string) => Promise<void>;
  error?: string;
}) {
  return (
    <main className="login">
      <section className="login-story">
        <a className="brand" href="#/">
          V<span className="brand-mark">X</span>
          <span>VaultX Pay</span>
        </a>
        <div>
          <span className="eyebrow">YOUR OPERATOR WORKSPACE</span>
          <h2>
            Clarity in
            <br />
            every transaction.
          </h2>
          <p>
            A focused view of your payment activity.
            <br />
            Secure by design. Simulator only.
          </p>
          <div className="story-lines" aria-hidden="true">
            <i />
            <i />
            <i />
          </div>
        </div>
        <span className="muted">VaultX Pay · Secure operator access</span>
      </section>
      <section className="login-form">
        <div className="login-card">
          <span className="mode">● SIMULATOR MODE</span>
          <h1 tabIndex={-1}>Welcome back</h1>
          <p className="muted">Sign in to your operator workspace.</p>
          {message && <p role="status">{message}</p>}
          <form
            method="post"
            action="/dashboard-api/auth/login"
            onSubmit={(event) => {
              event.preventDefault();
              const form = event.currentTarget;
              const data = new FormData(form);
              const username = field(data, 'username'),
                password = field(data, 'password');
              form.reset();
              void onLogin(username, password);
            }}
          >
            <label htmlFor="username">Username</label>
            <input
              id="username"
              name="username"
              autoComplete="username"
              required
              minLength={3}
              maxLength={80}
              autoCapitalize="none"
              spellCheck={false}
            />
            <label htmlFor="password">Password</label>
            <input
              id="password"
              name="password"
              type="password"
              autoComplete="current-password"
              required
              minLength={15}
              maxLength={128}
            />
            {error && <Alert>{error}</Alert>}
            <button className="primary">Sign in securely →</button>
          </form>
          <button className="invitation-open" onClick={onEnroll}>
            Accept a test invitation
          </button>
          <p className="login-note">
            Access is limited to your assigned operator.
            <br />
            Need help signing in? Contact your administrator.
          </p>
        </div>
      </section>
    </main>
  );
}
function GatewaySummary({ onExpired }: { onExpired: (error: unknown) => void }) {
  const { data, error } = useProtectedRead('summary', api.status, onExpired);
  const state = data
    ? 'Gateway responding'
    : error
      ? 'Gateway status unavailable'
      : 'Checking gateway…';
  return (
    <a href="#/status" className="gateway-summary" aria-live="polite">
      ◉ {state} <span>View system status →</span>
    </a>
  );
}
function Payments({
  overview,
  onExpired,
  terminal = false,
  statusAvailable = true,
}: {
  overview: boolean;
  onExpired: (error: unknown) => void;
  terminal?: boolean;
  statusAvailable?: boolean;
}) {
  const [offset, setOffset] = useState(0);
  const [status, setStatus] = useState('');
  const [currency, setCurrency] = useState('');
  const [revision, setRevision] = useState(0);
  const read = useCallback(
    (signal: AbortSignal) => api.history(offset, status, currency, signal),
    [offset, status, currency],
  );
  const { data, error, refreshing } = useProtectedRead(
    `${offset}:${status}:${currency}:${revision}`,
    read,
    onExpired,
  );
  return (
    <>
      <header className="page-heading">
        <div>
          <span className="eyebrow">
            {terminal ? 'ASSIGNED TERMINAL ACTIVITY' : 'OPERATOR WORKSPACE'}
          </span>
          <h1>{overview ? 'Overview' : 'Payments'}</h1>
          <p>
            {overview
              ? terminal
                ? 'Your authorized terminal activity, in focus.'
                : 'Your payment activity, in focus.'
              : 'Explore your simulated transaction history.'}
          </p>
        </div>
        <span className="read-only">◈ Read-only access</span>
      </header>
      {overview && statusAvailable && <GatewaySummary onExpired={onExpired} />}
      {overview && data && (
        <div className="stats">
          <article className="stat">
            <span>Payments on this page</span>
            <strong>{data.payments.length}</strong>
            <small>Latest page · up to 10 payments</small>
          </article>
          <article className="stat">
            <span>Succeeded on this page</span>
            <strong>{data.payments.filter((p) => p.status === 'succeeded').length}</strong>
            <small>Page scope only · not a total</small>
          </article>
          <article className="stat">
            <span>Environment</span>
            <strong className="environment">Simulator</strong>
            <small>No real money is processed</small>
          </article>
        </div>
      )}
      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>{overview ? 'Recent transactions' : 'Transaction history'}</h2>
            <p>
              {terminal
                ? 'Only simulator payments authorized for this account'
                : 'Simulator payments for your operator'}
            </p>
          </div>
          <button className="secondary" onClick={() => setRevision((v) => v + 1)}>
            Refresh
          </button>
        </div>
        {!overview && (
          <form
            className="filters"
            onSubmit={(event) => {
              event.preventDefault();
              const fields = new FormData(event.currentTarget);
              setStatus(field(fields, 'status'));
              setCurrency(field(fields, 'currency').toUpperCase());
              setOffset(0);
            }}
          >
            <label>
              Status
              <select name="status" aria-label="Status" defaultValue="">
                <option value="">All statuses</option>
                {['pending', 'succeeded', 'failed', 'cancelled'].map((s) => (
                  <option key={s}>{s}</option>
                ))}
              </select>
            </label>
            <label>
              Currency
              <input
                name="currency"
                placeholder="e.g. EUR"
                pattern="[A-Za-z]{3}|"
                maxLength={3}
                aria-label="Currency (three-letter code)"
              />
            </label>
            <button className="secondary">Apply filters</button>
          </form>
        )}
        {error ? <Alert>{error}</Alert> : data ? <Table payments={data.payments} /> : <Loading />}
        {data && (
          <p className="read-freshness">
            {refreshing
              ? 'Checking current access…'
              : 'Server-verified · rechecked every 15 seconds while visible'}
          </p>
        )}
        {data && (
          <footer className="pagination">
            <span>
              {data.payments.length
                ? `Showing ${offset + 1}–${offset + data.payments.length}`
                : '0 matching payments'}{' '}
              · page scope
            </span>
            {overview ? (
              <a href="#/payments">View all payments →</a>
            ) : (
              <div>
                <button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 10))}>
                  ← Previous
                </button>
                <button
                  disabled={!data.pagination.hasMore || offset >= 10000}
                  onClick={() => setOffset(offset + 10)}
                >
                  Next →
                </button>
              </div>
            )}
          </footer>
        )}
      </section>
      <div className="security-note">
        ◈ {terminal ? 'Server-enforced terminal scope' : 'Operator-scoped data'} · Read-only
        workspace · Simulator payments only
      </div>
    </>
  );
}
function Detail({ id, onExpired }: { id: string; onExpired: (error: unknown) => void }) {
  const read = useCallback((signal: AbortSignal) => api.detail(id, signal), [id]);
  const { data: payment, error } = useProtectedRead(id, read, onExpired);
  return (
    <>
      <a className="back" href="#/payments">
        ← Payment history
      </a>
      <header className="page-heading">
        <div>
          <span className="eyebrow">TRANSACTION DETAIL</span>
          <h1>Payment details</h1>
          <p>A read-only record of this simulated payment.</p>
        </div>
      </header>
      {error ? (
        <Alert>{error}</Alert>
      ) : !payment ? (
        <Loading />
      ) : (
        <section className="panel detail-panel">
          <div className="payment-total">
            <span className="eyebrow">PAYMENT AMOUNT</span>
            <h2>{money(payment)}</h2>
            <Badge status={payment.status} />
          </div>
          <dl>
            {[
              ['Payment ID', payment.id],
              ['Currency', payment.currency],
              ['Provider', 'Simulator'],
              ['Created', date(payment.createdAt)],
              ['Updated', date(payment.updatedAt)],
            ].map(([label, value]) => (
              <div key={label}>
                <dt>{label}</dt>
                <dd>{value}</dd>
              </div>
            ))}
          </dl>
        </section>
      )}
    </>
  );
}
function Status({ onExpired }: { onExpired: (error: unknown) => void }) {
  const { data, error } = useProtectedRead('status', api.status, onExpired);
  return (
    <>
      <header className="page-heading">
        <div>
          <span className="eyebrow">SYSTEM VISIBILITY</span>
          <h1>System status</h1>
          <p>A point-in-time check from the authenticated gateway.</p>
        </div>
      </header>
      {error ? (
        <Alert>{error}</Alert>
      ) : !data ? (
        <Loading />
      ) : (
        <section className="panel status-panel">
          <span className="mode">● SIMULATOR MODE</span>
          <h2>Gateway is responding</h2>
          <dl>
            {[
              ['Gateway', 'Responding'],
              ['Database', 'Reachable during this check'],
              ['Provider', 'Simulator only'],
              ['Real payments', 'Disabled'],
            ].map(([k, v]) => (
              <div key={k}>
                <dt>{k}</dt>
                <dd>{v}</dd>
              </div>
            ))}
          </dl>
          <p className="muted">
            Connectivity does not establish production readiness, uptime, or settlement capability.
          </p>
        </section>
      )}
    </>
  );
}
export function App() {
  const [auth] = useState(() => new DashboardAuth());
  const state = useSyncExternalStore(auth.subscribe, auth.snapshot);
  const [view, setView] = useState<View>(route);
  const [enrolling, setEnrolling] = useState(false);
  useEffect(() => {
    if (state.phase !== 'anonymous') setEnrolling(false);
  }, [state.phase]);
  const version = auth.version();
  useEffect(() => auth.start(), [auth]);
  useEffect(() => {
    const hash = () => setView(route());
    window.addEventListener('hashchange', hash);
    return () => window.removeEventListener('hashchange', hash);
  }, []);
  useEffect(() => {
    if (['authenticated', 'anonymous', 'blocked'].includes(state.phase)) {
      const heading = document.querySelector<HTMLElement>('main h1');
      if (heading) {
        heading.tabIndex = -1;
        heading.focus();
      }
    }
  }, [state.phase, state.identity?.user.id, view, version]);
  const expire = useCallback(
    (error: unknown) => {
      if (error instanceof ApiError && error.status === 401) auth.expire(version);
      else if (!(error instanceof ApiError) || ![400, 404].includes(error.status))
        auth.suspendReads(
          version,
          error instanceof ApiError && error.status === 403
            ? error.message
            : 'Payment data could not be verified. Protected records are closed. Check your session before continuing.',
        );
    },
    [auth, version],
  );
  if (['passkey-required', 'passkey', 'enrollment'].includes(state.phase))
    return <PasskeyGate controller={auth} state={state} />;
  if (state.phase === 'anonymous' && enrolling)
    return <InvitationAcceptance controller={auth} onClose={() => setEnrolling(false)} />;
  if (['checking', 'login', 'logout'].includes(state.phase))
    return (
      <main className="boot">
        <Loading />
        {state.phase === 'login' && (
          <p>Sign-in is pending. Wait for confirmation; do not submit another attempt.</p>
        )}
        {state.phase === 'logout' && <p>Signing out. Protected views remain closed.</p>}
      </main>
    );
  if (state.phase === 'blocked')
    return (
      <main className="boot">
        <h1 tabIndex={-1}>Session needs attention</h1>
        <Alert>{state.error}</Alert>
        <button
          onClick={() => {
            void auth.check(true);
          }}
        >
          Check session again
        </button>
      </main>
    );
  if (state.phase !== 'authenticated' || !state.identity)
    return (
      <Login
        onLogin={auth.login}
        error={state.error}
        message={state.message}
        onEnroll={() => setEnrolling(true)}
      />
    );
  const identity = state.identity;
  const access = identity.readAccess ?? { scope: 'operator', payments: true, status: true };
  return (
    <div className="app-shell" key={`${version}:${identity.user.id}:${identity.operator.id}`}>
      <a
        href="#main-content"
        className="skip-link"
        onClick={(e) => {
          e.preventDefault();
          document.getElementById('main-content')?.focus();
        }}
      >
        Skip to content
      </a>
      <aside className="sidebar">
        <a className="brand" href="#/">
          V<span className="brand-mark">X</span>
          <span>VaultX Pay</span>
        </a>
        <span className="nav-caption">WORKSPACE</span>
        <nav aria-label="Main navigation">
          {[
            ['overview', '◫', 'Overview'],
            ['payments', '⇄', 'Payments'],
            ['status', '◉', 'System status'],
          ]
            .filter(
              ([path]) =>
                path === 'overview' || (path === 'payments' ? access.payments : access.status),
            )
            .map(([path, icon, label]) => (
              <a
                key={path}
                href={path === 'overview' ? '#/' : `#/${path}`}
                aria-current={view.split('/')[0] === path ? 'page' : undefined}
              >
                <span aria-hidden="true">{icon}</span>
                {label}
              </a>
            ))}
        </nav>
        <div className="sidebar-bottom">
          <span className="mode">● SIMULATOR MODE</span>
          <p>
            No real money movement.
            <br />
            {access.scope === 'terminal'
              ? 'Assigned terminal workspace.'
              : 'Read-only operator workspace.'}
          </p>
        </div>
      </aside>
      <div className="workspace">
        <header className="topbar">
          <span className="breadcrumb">
            Workspace <span>/</span>{' '}
            {view.startsWith('payments/')
              ? 'Payment detail'
              : view.charAt(0).toUpperCase() + view.slice(1)}
          </span>
          <div className="account">
            <span className="avatar" aria-hidden="true">
              {identity.user.username.slice(0, 2).toUpperCase()}
            </span>
            <span>
              {identity.user.username}
              <small>
                {access.scope === 'terminal' ? 'Submerchant viewer' : 'Operator viewer'}
              </small>
            </span>
            <button
              onClick={() => {
                void auth.logout();
              }}
            >
              Sign out
            </button>
          </div>
        </header>
        <main id="main-content" tabIndex={-1}>
          <div className="operator-id">
            {access.scope === 'terminal' ? (
              'Assigned-terminal visibility · Verified by the gateway'
            ) : (
              <>
                Operator <span className="mono">{identity.operator.id}</span>
              </>
            )}
          </div>
          {(view === 'status' && !access.status) || (view !== 'status' && !access.payments) ? (
            <section className="panel access-denied">
              <h1>Read access unavailable</h1>
              <p>
                This account does not currently have access to this view. Ask your administrator to
                review access. No payment records are displayed.
              </p>
              <button onClick={() => void auth.check(true)}>Check access again</button>
            </section>
          ) : view === 'status' ? (
            <Status onExpired={expire} />
          ) : view.startsWith('payments/') ? (
            <Detail key={view} id={view.slice(9)} onExpired={expire} />
          ) : (
            <Payments
              key={view}
              overview={view === 'overview'}
              onExpired={expire}
              terminal={access.scope === 'terminal'}
              statusAvailable={access.status}
            />
          )}
        </main>
        <footer className="app-footer">
          VaultX Pay <span>Secure visibility. Simulated payments.</span>
        </footer>
      </div>
    </div>
  );
}
if (import.meta.env.MODE !== 'test' && document.getElementById('root'))
  createRoot(document.getElementById('root')!).render(<App />);
