import React, { useCallback, useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { ownerApi, OwnerApiError, type OwnerIdentity, type ManagedOperator } from './api';
import '../styles.css';
import './owner.css';

const failure = (error: unknown) =>
  error instanceof OwnerApiError ? error.message : 'The owner request could not be completed.';
type View = 'overview' | 'operators' | 'accounts' | 'team' | 'audit';
const views: [View, string][] = [
  ['overview', 'Owner overview'],
  ['operators', 'Operators'],
  ['accounts', 'Client accounts'],
  ['team', 'Team and permissions'],
  ['audit', 'Audit activity'],
];
function currentView(): View {
  const key = location.hash.slice(2);
  return views.some(([v]) => v === key) ? (key as View) : 'overview';
}
function Alert({ children }: { children: React.ReactNode }) {
  return (
    <p className="alert" role="alert">
      {children}
    </p>
  );
}
function Pager({
  offset,
  more,
  update,
}: {
  offset: number;
  more: boolean;
  update: (n: number) => void;
}) {
  return (
    <div className="pagination">
      <span>Page {offset / 20 + 1} · bounded view</span>
      <div>
        <button disabled={offset === 0} onClick={() => update(offset - 20)}>
          ← Previous
        </button>
        <button disabled={!more || offset >= 10000} onClick={() => update(offset + 20)}>
          Next →
        </button>
      </div>
    </div>
  );
}
function useResource<T>(load: (signal: AbortSignal) => Promise<T>, expired: () => void) {
  const [state, setState] = useState<{ value?: T; error?: string }>({});
  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    setState({});
    void load(controller.signal)
      .then((value) => {
        if (active) setState({ value });
      })
      .catch((error: unknown) => {
        if (!active) return;
        if (error instanceof OwnerApiError && (error.status === 401 || error.status === 403)) {
          expired();
          return;
        }
        setState({ error: failure(error) });
      });
    return () => {
      active = false;
      controller.abort();
    };
  }, [load, expired]);
  return state;
}
function Operators({
  identity,
  view,
  expired,
}: {
  identity: OwnerIdentity;
  view: View;
  expired: (notice?: string) => void;
}) {
  const [offset, setOffset] = useState(0),
    [selected, setSelected] = useState<string>(),
    [revision, setRevision] = useState(0);
  const load = useCallback((s: AbortSignal) => ownerApi.operators(offset, s), [offset, revision]);
  const state = useResource(load, expired);
  if (!identity.permissions.includes('platform.clients.read'))
    return <Alert>Operator directory permission is required.</Alert>;
  return (
    <>
      <section className="panel">
        <div className="panel-heading">
          <h2>Client operator directory</h2>
          <button
            onClick={() => {
              setSelected(undefined);
              setRevision((v) => v + 1);
            }}
          >
            Reload directory
          </button>
        </div>
        {state.error ? (
          <Alert>{state.error}</Alert>
        ) : !state.value ? (
          <p role="status" className="loading">
            Loading directory…
          </p>
        ) : (
          <>
            <div className="table-wrap">
              <table>
                <caption className="sr-only">Authorized client operators</caption>
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Code</th>
                    <th>Status</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {state.value.operators.map((operator) => (
                    <tr key={operator.id}>
                      <td>{operator.name}</td>
                      <td>{operator.code}</td>
                      <td>{operator.status}</td>
                      <td>
                        <button onClick={() => setSelected(operator.id)}>
                          Inspect {operator.code}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {state.value.operators.length === 0 && (
              <p className="empty">No operators on this page.</p>
            )}
            <Pager
              offset={offset}
              more={state.value.pagination.hasMore}
              update={(n) => {
                setSelected(undefined);
                setOffset(n);
              }}
            />
          </>
        )}
      </section>
      {selected && (
        <OperatorDetails
          key={selected + revision}
          target={selected}
          identity={identity}
          view={view}
          expired={expired}
          changed={() => setRevision((v) => v + 1)}
        />
      )}
    </>
  );
}
function OperatorDetails({
  target,
  identity,
  view,
  expired,
  changed,
}: {
  target: string;
  identity: OwnerIdentity;
  view: View;
  expired: (notice?: string) => void;
  changed: () => void;
}) {
  const load = useCallback((s: AbortSignal) => ownerApi.operator(target, s), [target]);
  const state = useResource(load, expired);
  return (
    <section className="panel owner-section">
      <div className="panel-heading">
        <h2>Selected client</h2>
      </div>
      {state.error ? (
        <Alert>{state.error}</Alert>
      ) : !state.value ? (
        <p role="status" className="loading">
          Loading client…
        </p>
      ) : (
        <>
          <div className="owner-content">
            <dl>
              <div>
                <dt>Operator</dt>
                <dd>{state.value.name}</dd>
              </div>
              <div>
                <dt>Immutable ID</dt>
                <dd className="mono">{state.value.id}</dd>
              </div>
              <div>
                <dt>Status</dt>
                <dd>{state.value.status}</dd>
              </div>
              <div>
                <dt>Version</dt>
                <dd>{state.value.version}</dd>
              </div>
            </dl>
          </div>
          {view === 'operators' && identity.permissions.includes('platform.clients.manage') && (
            <OperatorControls operator={state.value} expired={expired} changed={changed} />
          )}
          {(view === 'accounts' || view === 'team') && (
            <Members target={target} expired={expired} />
          )}
          {view === 'team' && identity.permissions.includes('platform.clients.manage') && (
            <WithdrawControls operator={state.value} expired={expired} changed={changed} />
          )}
        </>
      )}
    </section>
  );
}
function OperatorControls({
  operator,
  expired,
  changed,
}: {
  operator: ManagedOperator;
  expired: (notice?: string) => void;
  changed: () => void;
}) {
  const [pending, setPending] = useState(false),
    [error, setError] = useState<string>();
  const live = useRef(true);
  useEffect(
    () => () => {
      live.current = false;
    },
    [],
  );
  const run = async (work: () => Promise<unknown>) => {
    if (pending) return;
    setPending(true);
    setError(undefined);
    try {
      await work();
      if (live.current) changed();
    } catch (e) {
      if (!live.current) return;
      if (e instanceof OwnerApiError && (e.status === 401 || e.status === 403)) expired();
      else if (!(e instanceof OwnerApiError) || e.status >= 500)
        expired(
          'Change outcome not confirmed. Do not repeat this change. Check the owner session and reload current records before making another change.',
        );
      else setError(failure(e));
    } finally {
      if (live.current) setPending(false);
    }
  };
  return (
    <div className="owner-content">
      {error && <Alert>{error}</Alert>}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          const rawName = new FormData(e.currentTarget).get('name');
          const name = typeof rawName === 'string' ? rawName : '';
          void run(() =>
            ownerApi.updateOperator(operator.id, { name, expectedVersion: operator.version }),
          );
        }}
      >
        <label htmlFor="operator-name">Display name</label>
        <input
          id="operator-name"
          name="name"
          minLength={1}
          maxLength={120}
          required
          defaultValue={operator.name}
          disabled={pending}
        />
        <button disabled={pending} type="submit">
          Save display name
        </button>
      </form>
      <p className="muted">
        Status changes require fresh owner verification. Reactivation does not restore revoked human
        grants.
      </p>
      <button
        disabled={pending}
        onClick={() => {
          if (
            confirm(
              `Confirm ${operator.status === 'active' ? 'suspension' : 'reactivation'} of ${operator.code}?`,
            )
          )
            void run(() =>
              ownerApi.setStatus(operator.id, {
                status: operator.status === 'active' ? 'suspended' : 'active',
                expectedVersion: operator.version,
              }),
            );
        }}
      >
        {operator.status === 'active' ? 'Suspend client' : 'Reactivate client'}
      </button>
    </div>
  );
}
function Members({ target, expired }: { target: string; expired: () => void }) {
  const [offset, setOffset] = useState(0);
  const load = useCallback(
    (s: AbortSignal) => ownerApi.memberships(target, offset, s),
    [target, offset],
  );
  const state = useResource(load, expired);
  return (
    <>
      <div className="panel-heading">
        <h2>Retained client memberships</h2>
      </div>
      {state.error ? (
        <Alert>{state.error}</Alert>
      ) : !state.value ? (
        <p role="status" className="loading">
          Loading memberships…
        </p>
      ) : (
        <>
          <div className="table-wrap">
            <table>
              <caption className="sr-only">Selected client membership permissions</caption>
              <thead>
                <tr>
                  <th>Membership</th>
                  <th>Role / status</th>
                  <th>Active recorded grants</th>
                  <th>Version</th>
                </tr>
              </thead>
              <tbody>
                {state.value.members.map((m) => (
                  <tr key={m.id}>
                    <td className="mono">{m.id}</td>
                    <td>
                      {m.role} / {m.status}
                    </td>
                    <td>
                      {m.grants
                        .filter((g) => g.revokedAt === null)
                        .map((g) => g.permission)
                        .join(', ') || 'No active recorded grants'}
                    </td>
                    <td>{m.authorizationVersion}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pager offset={offset} more={state.value.pagination.hasMore} update={setOffset} />
        </>
      )}
      <p className="owner-content muted">
        No administrator promotion, invitation, delegation or credential creation is available in
        this foundation.
      </p>
    </>
  );
}
function WithdrawControls({
  operator,
  expired,
  changed,
}: {
  operator: ManagedOperator;
  expired: (notice?: string) => void;
  changed: () => void;
}) {
  const [busy, setBusy] = useState(false),
    [error, setError] = useState<string>();
  const live = useRef(true);
  useEffect(
    () => () => {
      live.current = false;
    },
    [],
  );
  const withdraw = async (permission: 'client.payments.read' | 'client.status.read') => {
    if (
      busy ||
      !confirm(
        `Permanently withdraw ${permission} for this client? Existing grants will not return automatically.`,
      )
    )
      return;
    setBusy(true);
    setError(undefined);
    try {
      await ownerApi.withdraw(operator.id, permission, operator.version);
      if (live.current) changed();
    } catch (e) {
      if (!live.current) return;
      if (e instanceof OwnerApiError && (e.status === 401 || e.status === 403)) expired();
      else if (!(e instanceof OwnerApiError) || e.status >= 500)
        expired(
          'Change outcome not confirmed. Do not repeat this change. Check the owner session and reload current records before making another change.',
        );
      else setError(failure(e));
    } finally {
      if (live.current) setBusy(false);
    }
  };
  return (
    <div className="owner-content">
      <h3>Withdraw existing client read entitlement</h3>
      <p className="muted">
        Withdrawal only. Issuance, regrant and privilege promotion remain unavailable.
      </p>
      {error && <Alert>{error}</Alert>}
      <div className="owner-actions">
        <button
          disabled={busy}
          onClick={() => {
            void withdraw('client.payments.read');
          }}
        >
          Withdraw payment read
        </button>
        <button
          disabled={busy}
          onClick={() => {
            void withdraw('client.status.read');
          }}
        >
          Withdraw status read
        </button>
      </div>
    </div>
  );
}
function Audit({ expired }: { expired: () => void }) {
  const [offset, setOffset] = useState(0);
  const load = useCallback((s: AbortSignal) => ownerApi.audit(offset, s), [offset]);
  const state = useResource(load, expired);
  return (
    <section className="panel">
      <div className="panel-heading">
        <h2>Privileged activity</h2>
      </div>
      {state.error ? (
        <Alert>{state.error}</Alert>
      ) : !state.value ? (
        <p role="status" className="loading">
          Loading audit history…
        </p>
      ) : (
        <>
          <div className="table-wrap">
            <table>
              <caption className="sr-only">Administrative audit events</caption>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Action</th>
                  <th>Target operator</th>
                  <th>Actor</th>
                </tr>
              </thead>
              <tbody>
                {state.value.events.map((event) => (
                  <tr key={event.id}>
                    <td>{new Date(event.occurredAt).toLocaleString()}</td>
                    <td>{event.action}</td>
                    <td className="mono">{event.operatorId ?? 'Platform'}</td>
                    <td>{event.actorId}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pager offset={offset} more={state.value.pagination.hasMore} update={setOffset} />
        </>
      )}
    </section>
  );
}
export function OwnerApp() {
  const [identity, setIdentity] = useState<OwnerIdentity>(),
    [state, setState] = useState<'checking' | 'ready' | 'blocked'>('checking'),
    [view, setView] = useState<View>(currentView),
    [epoch, setEpoch] = useState(0),
    [notice, setNotice] = useState<string>(),
    [logoutState, setLogoutState] = useState<'none' | 'pending' | 'confirmed' | 'uncertain'>(
      'none',
    );
  const generation = useRef(0),
    channel = useRef<BroadcastChannel | undefined>(undefined),
    closed = useRef(false),
    uncertain = useRef(false);
  const closeLocally = useCallback(() => {
    closed.current = true;
    try {
      sessionStorage.setItem('vaultx-owner-closed', 'true');
    } catch {
      /* Local denial remains in memory. */
    }
  }, []);
  const block = useCallback((message?: string) => {
    if (message) {
      uncertain.current = true;
      setNotice(message);
    }
    generation.current++;
    setIdentity(undefined);
    setState('blocked');
    setEpoch((v) => v + 1);
  }, []);
  const verify = useCallback(
    (explicit = false) => {
      if (uncertain.current && !explicit) return;
      if (explicit) {
        uncertain.current = false;
        setNotice(undefined);
      }
      if (closed.current) {
        block();
        return;
      }
      try {
        if (sessionStorage.getItem('vaultx-owner-closed') === 'true') {
          closed.current = true;
          block();
          return;
        }
      } catch {
        /* No authority comes from storage. */
      }
      const version = ++generation.current;
      setIdentity(undefined);
      setState('checking');
      setEpoch((v) => v + 1);
      void ownerApi
        .me()
        .then((value) => {
          if (generation.current === version) {
            setIdentity(value);
            setState('ready');
          }
        })
        .catch(() => {
          if (generation.current === version) block();
        });
    },
    [block],
  );
  useEffect(() => {
    verify();
    const hash = () => setView(currentView());
    const focus = () => verify();
    const visibility = () => {
      if (document.visibilityState === 'visible') verify();
      else block();
    };
    window.addEventListener('hashchange', hash);
    window.addEventListener('focus', focus);
    document.addEventListener('visibilitychange', visibility);
    if (typeof BroadcastChannel !== 'undefined') {
      channel.current = new BroadcastChannel('vaultx-owner-session');
      channel.current.onmessage = () => {
        closeLocally();
        block();
      };
    }
    return () => {
      generation.current++;
      window.removeEventListener('hashchange', hash);
      window.removeEventListener('focus', focus);
      document.removeEventListener('visibilitychange', visibility);
      channel.current?.close();
    };
  }, [verify, block, closeLocally]);
  const logout = () => {
    setLogoutState('pending');
    closeLocally();
    block();
    channel.current?.postMessage({ type: 'owner-session-closed' });
    void ownerApi
      .logout()
      .then(() => {
        setLogoutState('confirmed');
      })
      .catch(() => {
        setLogoutState('uncertain');
      });
  };
  if (state !== 'ready' || !identity)
    return (
      <main className="boot owner-unavailable">
        <span className="mode">SIMULATOR ONLY · OWNER REALM</span>
        <h1>
          {logoutState === 'pending'
            ? 'Signing out owner…'
            : logoutState === 'uncertain'
              ? 'Owner sign-out not confirmed'
              : logoutState === 'confirmed'
                ? 'Owner signed out'
                : state === 'checking'
                  ? 'Verifying owner session…'
                  : 'Owner authentication required'}
        </h1>
        <p>
          Owner access is separate from the client dashboard. A viewer session or payment API key
          cannot sign in here.
        </p>
        {notice && <Alert>{notice}</Alert>}
        {logoutState === 'uncertain' && (
          <Alert>
            Server sign-out could not be confirmed. Protected views remain closed in this tab. The
            server session may still be active; do not assume sign-out succeeded or automatically
            retry. Close this window and use the approved owner recovery process.
          </Alert>
        )}
        {state === 'blocked' && !closed.current && (
          <>
            <p>
              Owner enrollment, MFA and recovery require separately approved setup. No password-only
              or default owner sign-in is provided.
            </p>
            <button onClick={() => verify(true)}>Check existing owner session</button>
          </>
        )}
      </main>
    );
  return (
    <div className="app-shell">
      <a
        className="skip-link"
        href="#main-content"
        onClick={(event) => {
          event.preventDefault();
          document.getElementById('main-content')?.focus();
        }}
      >
        Skip to content
      </a>
      <aside className="sidebar">
        <a className="brand" href="#/">
          <span className="brand-mark">VX</span>
          <span>VaultX Pay</span>
        </a>
        <span className="nav-caption">OWNER MANAGEMENT</span>
        <nav aria-label="Owner navigation">
          {views.map(([key, label]) => (
            <a key={key} href={'#/' + key} aria-current={view === key ? 'page' : undefined}>
              {label}
            </a>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <span className="mode">SIMULATOR ONLY</span>
        </div>
      </aside>
      <div className="workspace">
        <header className="topbar">
          <span className="breadcrumb">Platform management · separate owner realm</span>
          <div className="account">
            <span>
              {identity.owner.username}
              <small>Verified owner session</small>
            </span>
            <button onClick={logout}>Sign out owner</button>
          </div>
        </header>
        <main id="main-content" key={identity.owner.id + epoch} tabIndex={-1}>
          <div className="page-heading">
            <div>
              <span className="eyebrow">GATEWAY MANAGEMENT</span>
              <h1>{views.find(([key]) => key === view)?.[1]}</h1>
              <p>Explicit platform authority. No client impersonation or payment writes.</p>
            </div>
          </div>
          {view === 'overview' ? (
            <>
              <section className="panel owner-content">
                <h2>Owner capabilities</h2>
                <p>Only the server-authorized actions below are available in this session.</p>
                <ul>
                  {identity.permissions.map((p) => (
                    <li key={p}>{p}</li>
                  ))}
                </ul>
                <p className="muted">
                  No balances, settlement totals or account counts are fabricated. Select Operators
                  to inspect the bounded directory.
                </p>
              </section>
            </>
          ) : view === 'audit' ? (
            identity.permissions.includes('platform.audit.read') ? (
              <Audit expired={block} />
            ) : (
              <Alert>Platform audit permission is required.</Alert>
            )
          ) : !identity.permissions.includes('platform.clients.read') ? (
            <Alert>Operator directory permission is required.</Alert>
          ) : (
            <Operators key={view} identity={identity} view={view} expired={block} />
          )}
        </main>
        <footer className="app-footer">
          VaultX Pay<span>Privileged actions are independently authorized and audited.</span>
        </footer>
      </div>
    </div>
  );
}
const element = document.getElementById('owner-root');
if (element) createRoot(element).render(<OwnerApp />);
