import { useEffect, useRef, useState, useSyncExternalStore, type FormEvent } from 'react';
import { createRoot } from 'react-dom/client';
import { DashboardAuth } from '../auth';
import { merchantApi, MerchantApiError, type MerchantIdentity, type MerchantMember } from './api';
import '../styles.css';
import './styles.css';
const auth = new DashboardAuth();
const unconfirmedKey = 'vaultx-merchant-write-unconfirmed';
function unconfirmed() {
  try {
    return sessionStorage.getItem(unconfirmedKey) === 'true';
  } catch {
    return false;
  }
}
type Screen = 'Overview' | 'Team and permissions' | 'Terminals' | 'Audit activity';
export function MerchantWorkspace({
  identity,
  expired,
  pendingChange,
}: {
  identity: MerchantIdentity;
  expired: () => void;
  pendingChange?: (pending: boolean) => void;
}) {
  const [screen, setScreen] = useState<Screen>('Overview');
  const [offset, setOffset] = useState(0);
  const [members, setMembers] = useState<MerchantMember[]>([]);
  const [terminals, setTerminals] = useState<
    Awaited<ReturnType<typeof merchantApi.terminals>>['terminals']
  >([]);
  const [events, setEvents] = useState<Awaited<ReturnType<typeof merchantApi.audit>>['events']>([]);
  const [more, setMore] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const [closed, setClosed] = useState(unconfirmed);
  const [reload, setReload] = useState(0);
  const generation = useRef(0),
    pending = useRef(false);
  const can = (code: string) => identity.permissions.some((p) => p === code);
  useEffect(() => {
    const epoch = ++generation.current,
      controller = new AbortController();
    setMembers([]);
    setTerminals([]);
    setEvents([]);
    setMore(false);
    if (!closed) setError('');
    if (closed || screen === 'Overview')
      return () => {
        generation.current++;
        controller.abort();
      };
    const request =
      screen === 'Team and permissions' && can('client.users.read')
        ? merchantApi.members(offset, controller.signal)
        : screen === 'Terminals' && can('client.terminals.read')
          ? merchantApi.terminals(offset, controller.signal)
          : screen === 'Audit activity' && can('client.audit.read')
            ? merchantApi.audit(offset, controller.signal)
            : undefined;
    if (!request) {
      setError('You do not have permission to view this screen.');
      return () => {
        generation.current++;
        controller.abort();
      };
    }
    setBusy(true);
    void request
      .then((data) => {
        if (epoch !== generation.current || controller.signal.aborted) return;
        if ('members' in data) setMembers(data.members);
        if ('terminals' in data) setTerminals(data.terminals);
        if ('events' in data) setEvents(data.events);
        setMore(data.pagination.hasMore);
      })
      .catch((failure: unknown) => {
        if (epoch !== generation.current || controller.signal.aborted) return;
        setMembers([]);
        setTerminals([]);
        setEvents([]);
        if (failure instanceof MerchantApiError && [401, 403].includes(failure.status)) {
          setClosed(true);
          expired();
        } else setError('The requested data is unavailable. No previous data is displayed.');
      })
      .finally(() => {
        if (epoch === generation.current) setBusy(false);
      });
    return () => {
      generation.current++;
      controller.abort();
    };
    // Permission identity is immutable for this keyed workspace.
  }, [screen, offset, reload, closed]);
  useEffect(
    () => () => {
      generation.current++;
    },
    [],
  );
  async function mutate(work: () => Promise<unknown>, success: string) {
    if (pending.current || closed) return;
    pending.current = true;
    pendingChange?.(true);
    setBusy(true);
    setError('');
    setNotice('');
    const epoch = generation.current;
    try {
      // Secret-free per-tab denial evidence survives route remounts/reloads.
      // Storage failure prevents issuing a write without this safeguard.
      sessionStorage.setItem(unconfirmedKey, 'true');
      await work();
      sessionStorage.removeItem(unconfirmedKey);
      if (epoch === generation.current) {
        setNotice(success);
        setMembers([]);
        setReload((v) => v + 1);
      }
    } catch (failure) {
      setMembers([]);
      setTerminals([]);
      setEvents([]);
      setClosed(true);
      setError(
        failure instanceof MerchantApiError && failure.status === 409
          ? failure.message
          : 'The change could not be confirmed. No automatic retry is permitted. Recheck your session and records before continuing.',
      );
    } finally {
      pending.current = false;
      pendingChange?.(false);
      if (epoch === generation.current) setBusy(false);
    }
  }
  function invite(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const selected = form
      .getAll('permission')
      .filter(
        (value): value is 'client.payments.read' | 'client.status.read' =>
          value === 'client.payments.read' || value === 'client.status.read',
      );
    if (!selected.length) {
      setError('Select at least one delegated permission.');
      return;
    }
    const username = form.get('username');
    if (typeof username !== 'string') return;
    void mutate(
      () =>
        merchantApi.invite(identity, {
          username,
          permissions: selected,
          terminalIds: [],
        }),
      'Pending invitation recorded. No account, activation token or credential was created.',
    );
  }
  return (
    <div className="merchant-layout">
      <aside>
        <a
          className="merchant-brand"
          href="/merchant/"
          aria-disabled={busy || closed}
          onClick={(event) => {
            if (busy || closed) event.preventDefault();
          }}
        >
          VaultX <span>Pay</span>
        </a>
        <p>Merchant management</p>
        <nav aria-label="Merchant navigation">
          {(['Overview', 'Team and permissions', 'Terminals', 'Audit activity'] as Screen[]).map(
            (item) => (
              <button
                disabled={busy || closed}
                aria-current={screen === item ? 'page' : undefined}
                key={item}
                onClick={() => {
                  setScreen(item);
                  setOffset(0);
                  setNotice('');
                }}
              >
                {item}
              </button>
            ),
          )}
        </nav>
        <p>
          Payment history is available only through the separately configured read-only dashboard.
        </p>
      </aside>
      <main>
        <header>
          <div>
            <p className="eyebrow">SIMULATOR-ONLY · MANAGEMENT FOUNDATION</p>
            <h1>{screen}</h1>
          </div>
          <button
            disabled={busy}
            onClick={() => {
              setMembers([]);
              setTerminals([]);
              setEvents([]);
              setClosed(true);
              expired();
            }}
          >
            Recheck session
          </button>
        </header>
        <p className="merchant-warning">
          Invitation activation and credential delivery are not enabled. Terminal assignments and
          terminal-scoped payment reads require a separate reviewed milestone. No real payment
          operation is available.
        </p>
        {error && <p role="alert">{error}</p>}
        {notice && <p role="status">{notice}</p>}
        {closed ? (
          <p>
            Protected records are closed. An earlier change may be unconfirmed; inspect its outcome
            before any separately authorized new action. Session rechecks do not automatically retry
            or clear this safeguard.
          </p>
        ) : (
          <>
            {screen === 'Overview' && (
              <section>
                <h2>Authorized merchant workspace</h2>
                <p>
                  Signed in as {identity.user.username}. Server-side membership, status and
                  permissions are checked for every management request.
                </p>
                <p>
                  Tenant reference: <code>{identity.operator.id}</code>
                </p>
                <p>Available permissions: {identity.permissions.join(', ') || 'None'}</p>
              </section>
            )}
            {screen === 'Team and permissions' && (
              <>
                <section>
                  <h2>Team members</h2>
                  {busy && <p role="status">Loading…</p>}
                  <div className="merchant-table">
                    <table>
                      <thead>
                        <tr>
                          <th>Username</th>
                          <th>Kind</th>
                          <th>Status</th>
                          <th>Revision</th>
                          <th>Restricted actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {members.map((member) => (
                          <tr key={member.id}>
                            <td>{member.username}</td>
                            <td>{member.kind ?? 'Existing viewer'}</td>
                            <td>{member.status}</td>
                            <td>{member.version}</td>
                            <td>
                              {member.kind === 'submerchant' &&
                                member.status === 'active' &&
                                member.sponsorMembershipId === identity.membership.id && (
                                  <>
                                    {can('client.users.manage_subaccounts') && (
                                      <button
                                        disabled={busy}
                                        onClick={() =>
                                          void mutate(
                                            () => merchantApi.disable(identity, member),
                                            'Restricted membership disabled.',
                                          )
                                        }
                                      >
                                        Disable {member.username}
                                      </button>
                                    )}
                                    {can('client.permissions.delegate') && (
                                      <button
                                        disabled={busy}
                                        onClick={() =>
                                          void mutate(
                                            () =>
                                              merchantApi.withdraw(
                                                identity,
                                                member,
                                                'client.payments.read',
                                              ),
                                            'Payment-read grant permanently withdrawn.',
                                          )
                                        }
                                      >
                                        Withdraw payment read for {member.username}
                                      </button>
                                    )}
                                  </>
                                )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  {!busy && !members.length && <p>No members are available on this page.</p>}
                </section>
                {can('client.users.manage_subaccounts') && can('client.permissions.delegate') && (
                  <section>
                    <h2>Record a submerchant invitation</h2>
                    <p>
                      This records pending intent only. It does not send an email or create an
                      account, API key or activation credential.
                    </p>
                    <form onSubmit={invite}>
                      <label>
                        Username
                        <input
                          name="username"
                          required
                          minLength={3}
                          maxLength={80}
                          pattern="[a-z0-9][a-z0-9_.-]{2,79}"
                          autoComplete="off"
                        />
                      </label>
                      <fieldset>
                        <legend>Explicit delegated permissions</legend>
                        {(['client.payments.read', 'client.status.read'] as const)
                          .filter(can)
                          .map((code) => (
                            <label className="merchant-check" key={code}>
                              <input type="checkbox" name="permission" value={code} />
                              {code}
                            </label>
                          ))}
                      </fieldset>
                      <button disabled={busy}>Record pending invitation</button>
                    </form>
                  </section>
                )}
              </>
            )}
            {screen === 'Terminals' && (
              <section>
                <h2>Terminal directory</h2>
                <p>
                  Read-only registered terminal metadata. This release does not assign terminal
                  access.
                </p>
                {terminals.map((terminal) => (
                  <article key={terminal.id}>
                    <h3>{terminal.name}</h3>
                    <p>
                      {terminal.code} · {terminal.status}
                    </p>
                  </article>
                ))}
                {!busy && !terminals.length && <p>No registered terminals on this page.</p>}
              </section>
            )}
            {screen === 'Audit activity' && (
              <section>
                <h2>Merchant audit history</h2>
                <p>Only this authenticated merchant's administrative events are returned.</p>
                <ol>
                  {events.map((event) => (
                    <li key={event.id}>
                      <strong>{event.action}</strong> ·{' '}
                      <time dateTime={event.occurred_at}>
                        {new Date(event.occurred_at).toLocaleString()}
                      </time>
                      {event.target_version !== null && <> · Revision {event.target_version}</>}
                    </li>
                  ))}
                </ol>
                {!busy && !events.length && <p>No events on this page.</p>}
              </section>
            )}
            {screen !== 'Overview' && (
              <div className="merchant-pages">
                <button disabled={busy || offset === 0} onClick={() => setOffset((v) => v - 20)}>
                  Previous page
                </button>
                <span>Page {offset / 20 + 1}</span>
                <button
                  disabled={busy || !more || offset >= 10000}
                  onClick={() => setOffset((v) => v + 20)}
                >
                  Next page
                </button>
              </div>
            )}
          </>
        )}
      </main>
    </div>
  );
}
export function MerchantApp({ controller = auth }: { controller?: DashboardAuth }) {
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot);
  const [merchant, setMerchant] = useState<MerchantIdentity>();
  const [error, setError] = useState('');
  const [writePending, setWritePending] = useState(false);
  useEffect(() => controller.start(), [controller]);
  useEffect(() => {
    setMerchant(undefined);
    setError('');
    if (state.phase !== 'authenticated' || !state.identity) return;
    const identity = state.identity,
      controller = new AbortController();
    void merchantApi
      .me(controller.signal)
      .then((value) => {
        if (controller.signal.aborted) return;
        if (value.user.id !== identity.user.id || value.operator.id !== identity.operator.id)
          throw new MerchantApiError(401);
        setMerchant(value);
      })
      .catch(() => {
        if (!controller.signal.aborted)
          setError('Merchant administration is not available for this session.');
      });
    return () => controller.abort();
  }, [state]);
  if (
    state.phase !== 'authenticated' ||
    !merchant ||
    merchant.user.id !== state.identity?.user.id ||
    merchant.operator.id !== state.identity?.operator.id
  )
    return (
      <main className="merchant-closed">
        <h1>VaultX Pay · Merchant management</h1>
        <p role="status">
          {error ||
            (state.phase === 'checking'
              ? 'Checking your existing client session…'
              : 'An active, explicitly authorized merchant-administrator session is required.')}
        </p>
        {state.phase === 'anonymous' && (
          <form
            aria-label="Merchant sign-in"
            onSubmit={(event) => {
              event.preventDefault();
              const form = event.currentTarget,
                data = new FormData(form);
              const username = data.get('username'),
                password = data.get('password');
              form.reset();
              if (typeof username === 'string' && typeof password === 'string')
                void controller.login(username, password);
            }}
          >
            <label htmlFor="merchant-username">Username</label>
            <input
              id="merchant-username"
              name="username"
              autoComplete="username"
              required
              minLength={3}
              maxLength={80}
            />
            <label htmlFor="merchant-password">Password</label>
            <input
              id="merchant-password"
              name="password"
              type="password"
              autoComplete="current-password"
              required
              minLength={15}
              maxLength={128}
            />
            <button>Sign in securely</button>
          </form>
        )}
        {state.error && <p role="alert">{state.error}</p>}
        <button onClick={() => void controller.check(true)}>Check session</button>
      </main>
    );
  return (
    <>
      <div className="merchant-session">
        <span>{merchant.user.username}</span>
        <button
          disabled={writePending}
          onClick={() => {
            if (writePending) return;
            setMerchant(undefined);
            void controller.logout();
          }}
        >
          Sign out
        </button>
      </div>
      <MerchantWorkspace
        key={merchant.user.id + ':' + merchant.operator.id + ':' + merchant.membership.version}
        identity={merchant}
        pendingChange={setWritePending}
        expired={() => {
          setMerchant(undefined);
          void controller.check(true);
        }}
      />
    </>
  );
}
const root = document.getElementById('merchant-root');
if (root) createRoot(root).render(<MerchantApp />);
