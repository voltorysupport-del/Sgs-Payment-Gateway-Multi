import { api, ApiError, type Identity } from './api';

export type AuthState = {
  phase: 'checking' | 'anonymous' | 'authenticated' | 'login' | 'logout' | 'blocked';
  identity?: Identity;
  error?: string;
};
const lockName = 'vaultx-dashboard-auth';
const topic = 'vaultx-dashboard-session';
type Notice = 'auth-start' | 'auth-changed' | 'auth-unconfirmed';

// App-owned mutations outlive individual screens. Web Locks serialize cookie/CSRF
// sequences across this origin's tabs; notifications carry no identity or secrets.
export class DashboardAuth {
  private state: AuthState = { phase: 'checking' };
  private listeners = new Set<() => void>();
  private epoch = 0;
  private pending = false;
  private blocked = false;
  private stopped = false;
  private read?: AbortController;
  private channel?: BroadcastChannel;
  constructor(private readonly client = api) {}
  snapshot = (): AuthState => this.state;
  subscribe = (listener: () => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };
  private set(state: AuthState) {
    this.state = state;
    if (this.stopped) return;
    this.listeners.forEach((listener) => listener());
  }
  private invalidate() {
    this.epoch++;
    this.read?.abort();
  }
  private notice(value: Notice) {
    try {
      if (!this.stopped) this.channel?.postMessage(value);
    } catch {
      this.channel = undefined;
    }
  }
  private visible() {
    return document.visibilityState !== 'hidden';
  }
  private async locked<T>(work: () => Promise<T>, signal?: AbortSignal): Promise<T> {
    if (!navigator.locks) throw new Error('Session coordination unavailable.');
    return navigator.locks.request(lockName, { mode: 'exclusive', signal }, work);
  }
  start() {
    this.stopped = false;
    try {
      if (typeof BroadcastChannel !== 'undefined') this.channel = new BroadcastChannel(topic);
    } catch {
      this.channel = undefined;
    }
    if (this.channel) {
      this.channel.onmessage = (event: MessageEvent<unknown>) => {
        if (
          event.data !== 'auth-start' &&
          event.data !== 'auth-changed' &&
          event.data !== 'auth-unconfirmed'
        )
          return;
        // An unconfirmed local operation always requires an explicit reconciliation.
        if (this.pending || this.blocked) return;
        if (event.data === 'auth-unconfirmed') {
          this.block('Session change could not be confirmed. Check the session before continuing.');
          return;
        }
        void this.check();
      };
    }
    document.addEventListener('visibilitychange', this.visibility);
    window.addEventListener('pageshow', this.restore);
    void this.check();
    return () => {
      this.stopped = true;
      this.invalidate();
      this.channel?.close();
      document.removeEventListener('visibilitychange', this.visibility);
      window.removeEventListener('pageshow', this.restore);
    };
  }
  private visibility = () => {
    if (this.pending || this.blocked) return;
    if (!this.visible()) {
      this.invalidate();
      this.set({ phase: 'checking' });
    } else void this.check();
  };
  private restore = () => {
    void this.check();
  };
  check = async (explicit = false): Promise<void> => {
    if (this.pending || (this.blocked && !explicit) || !this.visible() || this.stopped) return;
    this.invalidate();
    const epoch = this.epoch;
    const controller = new AbortController();
    this.read = controller;
    this.set({ phase: 'checking' });
    try {
      const work = async () => {
        if (epoch !== this.epoch || this.pending) return;
        const identity = await this.client.me(controller.signal);
        if (epoch === this.epoch && !this.pending && this.visible()) {
          this.blocked = false;
          this.set({ phase: 'authenticated', identity });
        }
      };
      // Browsers without Web Locks can still read an existing session, but cannot
      // issue competing authentication mutations.
      if (navigator.locks) await this.locked(work, controller.signal);
      else await work();
    } catch (error) {
      if (epoch !== this.epoch || this.pending || controller.signal.aborted) return;
      if (error instanceof ApiError && error.status === 401) {
        this.blocked = false;
        this.set({ phase: 'anonymous' });
      } else this.block('The session could not be verified. Check the session before continuing.');
    }
  };
  private block(error: string) {
    this.invalidate();
    this.blocked = true;
    this.set({ phase: 'blocked', error });
  }
  version = () => this.epoch;
  expire = (version: number) => {
    if (version !== this.epoch || this.pending || this.blocked) return;
    this.invalidate();
    this.set({ phase: 'anonymous' });
  };
  login = (username: string, password: string) => this.mutate('login', username, password);
  logout = () => this.mutate('logout');
  private async mutate(kind: 'login' | 'logout', username?: string, password?: string) {
    if (this.pending || this.blocked || this.stopped) return;
    if (kind === 'login' && this.state.phase !== 'anonymous') return;
    if (kind === 'logout' && this.state.phase !== 'authenticated') return;
    this.pending = true;
    this.invalidate();
    const epoch = this.epoch;
    this.set({ phase: kind });
    try {
      await this.locked(async () => {
        if (this.stopped || epoch !== this.epoch) return;
        this.notice('auth-start');
        if (kind === 'login') {
          // A stale tab must first discover an already authenticated shared cookie.
          let existing: Identity | undefined;
          try {
            existing = await this.client.me();
          } catch (error) {
            if (!(error instanceof ApiError && error.status === 401)) throw error;
          }
          if (!existing) await this.client.login(username!, password!);
          const identity = existing ?? (await this.client.me());
          this.notice('auth-changed');
          if (epoch === this.epoch && !this.stopped)
            this.set(this.visible() ? { phase: 'authenticated', identity } : { phase: 'checking' });
        } else {
          await this.client.logout();
          // Terminal logout invalidates EVERY prior read, even without a channel.
          if (epoch === this.epoch && !this.stopped) {
            this.invalidate();
            this.set({ phase: 'anonymous' });
          } else this.set({ phase: 'checking' });
          this.notice('auth-changed');
        }
      });
    } catch (error) {
      if (kind === 'login' && error instanceof ApiError && [401, 429].includes(error.status)) {
        this.set({
          phase: 'anonymous',
          error: error.status === 401 ? 'Invalid username or password.' : error.message,
        });
        this.notice('auth-changed');
      } else {
        this.block(
          kind === 'logout'
            ? 'Sign-out could not be confirmed. Check the session before continuing.'
            : 'Sign-in could not be confirmed. Check the session before continuing.',
        );
        this.notice('auth-unconfirmed');
      }
    } finally {
      this.pending = false;
      // React may detach/restart the owner while a cookie response is in flight.
      // Reconcile only after settlement; an unconfirmed outcome remains blocked.
      if (
        !this.stopped &&
        epoch !== this.epoch &&
        !this.blocked &&
        this.state.phase !== 'anonymous'
      )
        void this.check();
    }
  }
}
