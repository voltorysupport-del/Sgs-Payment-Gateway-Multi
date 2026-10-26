/* global URL, Buffer */
import process from 'node:process';
// Isolated synthetic demonstration. Never imported by the gateway.
import http from 'node:http';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
export const PERMISSIONS = ['payments.read', 'payments.simulate', 'finance.read', 'audit.read'];
const COOKIE = 'vaultx_phase2_demo';
const text = (value, max = 80) =>
  typeof value === 'string' && value.trim().length > 0 && value.length <= max;
export function demoState() {
  const merchants = [
    {
      id: 'merchant-north',
      name: 'Northstar Commerce · Demo',
      status: 'active',
      version: 1,
      ceilings: [...PERMISSIONS],
      terminals: ['terminal-web', 'terminal-mobile'],
    },
    {
      id: 'merchant-orbit',
      name: 'Orbit Travel · Demo',
      status: 'active',
      version: 1,
      ceilings: [...PERMISSIONS],
      terminals: ['terminal-orbit'],
    },
  ];
  const users = [
    {
      id: 'user-analyst',
      merchantId: merchants[0].id,
      name: 'Alex · Demo Analyst',
      status: 'active',
      permissions: ['payments.read', 'finance.read'],
      terminals: ['terminal-web'],
      version: 1,
    },
    {
      id: 'user-orbit',
      merchantId: merchants[1].id,
      name: 'Morgan · Demo Operator',
      status: 'active',
      permissions: ['payments.read'],
      terminals: ['terminal-orbit'],
      version: 1,
    },
  ];
  const payments = Array.from({ length: 42 }, (_, i) => ({
    id: `demo-payment-${String(i + 1).padStart(3, '0')}`,
    merchantId: i < 30 ? merchants[0].id : merchants[1].id,
    terminal: i < 30 ? (i % 3 ? 'terminal-web' : 'terminal-mobile') : 'terminal-orbit',
    amountMinor: 100 + ((i * 1473) % 42000),
    currency: ['EUR', 'EUR', 'USD'][i % 3],
    status: ['succeeded', 'pending', 'failed', 'succeeded'][i % 4],
    country: ['DE', 'RO', 'NL'][i % 3],
    method: 'simulator-card',
    provider: 'simulator',
    createdAt: new Date(Date.UTC(2026, 9, 26 - (i % 14), 11, i)).toISOString(),
    attempts: [{ sequence: 1, provider: 'simulator', result: i % 4 === 2 ? 'failed' : 'accepted' }],
    webhooks: [],
  }));
  return { merchants, users, payments, invitations: [], audit: [], sessions: new Map() };
}
export async function startPreview({ port = 4175 } = {}) {
  let state = demoState();
  let origin;
  const log = (s, action, target, merchantId = null) =>
    state.audit.unshift({
      id: randomUUID(),
      actor: s?.role ?? 'demo',
      action,
      target,
      merchantId,
      occurredAt: new Date().toISOString(),
      simulated: true,
    });
  const server = http.createServer((req, res) => {
    const send = (status, value, mime = 'application/json') => {
      res.writeHead(status, { 'Content-Type': mime, 'Cache-Control': 'no-store' });
      res.end(mime === 'application/json' ? JSON.stringify(value) : value);
    };
    void (async () => {
      res.setHeader(
        'Content-Security-Policy',
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
      );
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('Referrer-Policy', 'no-referrer');
      if (
        req.headers.host !== new URL(origin).host ||
        (req.headers.origin && req.headers.origin !== origin) ||
        (req.headers['sec-fetch-site'] &&
          !['same-origin', 'none'].includes(req.headers['sec-fetch-site']))
      )
        return send(403, { error: 'Local demo origin required.' });
      if (!['GET', 'POST', 'PATCH'].includes(req.method))
        return send(405, { error: 'Method not supported.' });
      const url = new URL(req.url, origin);
      if (url.origin !== origin) return send(403, { error: 'Local demo only.' });
      if (req.method !== 'GET' && req.headers.origin !== origin)
        return send(403, { error: 'Local origin required.' });
      if (req.headers['content-encoding']) return send(415, { error: 'Compression not accepted.' });
      let raw = '';
      for await (const chunk of req) {
        raw += chunk;
        if (Buffer.byteLength(raw) > 8192) return send(413, { error: 'Body too large.' });
      }
      let body;
      try {
        body = raw ? JSON.parse(raw) : {};
      } catch {
        return send(400, { error: 'Invalid JSON.' });
      }
      const token = (req.headers.cookie ?? '')
        .split(';')
        .map((x) => x.trim())
        .find((x) => x.startsWith(COOKIE + '='))
        ?.slice(COOKIE.length + 1);
      const s = state.sessions.get(token);
      const merchant = s?.merchantId && state.merchants.find((m) => m.id === s.merchantId);
      const user = s?.userId && state.users.find((u) => u.id === s.userId);
      const active =
        s &&
        (s.role === 'owner' ||
          (merchant?.status === 'active' &&
            (s.role === 'merchant' ||
              (user?.status === 'active' && user.version === s.userVersion))));
      const csrf = () => active && req.headers['x-demo-csrf'] === s.csrf;
      const can = (p) =>
        active &&
        (s.role === 'owner' ||
          (merchant.ceilings.includes(p) &&
            (s.role === 'merchant' || user.permissions.includes(p))));
      const visible = (p) =>
        s?.role === 'owner' ||
        (p.merchantId === s?.merchantId &&
          (s.role === 'merchant' || user.terminals.includes(p.terminal)));
      if (url.pathname === '/demo/catalog' && req.method === 'GET')
        return send(200, {
          simulated: true,
          merchants: state.merchants.map(({ id, name }) => ({ id, name })),
          users: state.users
            .filter((u) => u.status === 'active')
            .map(({ id, name, merchantId }) => ({ id, name, merchantId })),
          invitations: state.invitations
            .filter((i) => !i.used)
            .map(({ id, name, merchantId }) => ({ id, name, merchantId })),
        });
      if (url.pathname === '/demo/login' && req.method === 'POST') {
        let chosen;
        if (body.role === 'owner') chosen = { role: 'owner' };
        if (
          body.role === 'merchant' &&
          state.merchants.some((m) => m.id === body.merchantId && m.status === 'active')
        )
          chosen = { role: 'merchant', merchantId: body.merchantId };
        if (body.role === 'submerchant') {
          const u = state.users.find((u) => u.id === body.userId && u.status === 'active');
          if (u && state.merchants.some((m) => m.id === u.merchantId && m.status === 'active'))
            chosen = {
              role: 'submerchant',
              merchantId: u.merchantId,
              userId: u.id,
              userVersion: u.version,
            };
        }
        if (!chosen) return send(403, { error: 'Demo account unavailable.' });
        if (state.sessions.size >= 100)
          return send(429, { error: 'Reset demo state to continue.' });
        if (token) state.sessions.delete(token);
        const id = randomBytes(32).toString('hex');
        state.sessions.set(id, { ...chosen, csrf: randomBytes(32).toString('hex') });
        res.setHeader('Set-Cookie', `${COOKIE}=${id}; HttpOnly; SameSite=Strict; Path=/`);
        return send(200, { simulated: true });
      }
      if (url.pathname === '/demo/activate' && req.method === 'POST') {
        const invitation = state.invitations.find((i) => i.id === body.invitationId && !i.used);
        if (
          !invitation ||
          !state.merchants.some((m) => m.id === invitation.merchantId && m.status === 'active')
        )
          return send(409, { error: 'Demo invitation unavailable.' });
        invitation.used = true;
        state.users.push({
          id: randomUUID(),
          merchantId: invitation.merchantId,
          name: invitation.name,
          status: 'active',
          permissions: [],
          terminals: [],
          version: 1,
        });
        log(null, 'demo.invitation.activated', invitation.name, invitation.merchantId);
        return send(200, { simulated: true });
      }
      if (url.pathname === '/demo/reset' && req.method === 'POST') {
        if (!csrf()) return send(403, { error: 'Demo session and CSRF required.' });
        state = demoState();
        res.setHeader('Set-Cookie', `${COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`);
        return send(200, { simulated: true });
      }
      if (url.pathname.startsWith('/api/')) {
        if (!active)
          return send(401, {
            error: 'Demo session expired or invalidated. Choose a demo role again.',
          });
        if (req.method !== 'GET' && !csrf()) return send(403, { error: 'Demo CSRF rejected.' });
        if (url.pathname === '/api/me' && req.method === 'GET')
          return send(200, {
            role: s.role,
            merchantId: s.merchantId,
            userId: s.userId,
            name:
              s.role === 'owner'
                ? 'VaultX Demo Owner'
                : s.role === 'merchant'
                  ? merchant.name
                  : user.name,
            csrf: s.csrf,
            permissions:
              s.role === 'submerchant'
                ? user.permissions.filter((p) => merchant.ceilings.includes(p))
                : PERMISSIONS,
            simulated: true,
          });
        if (url.pathname === '/api/logout' && req.method === 'POST') {
          state.sessions.delete(token);
          res.setHeader('Set-Cookie', `${COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`);
          return send(200, {});
        }
        if (url.pathname === '/api/merchants') {
          if (s.role !== 'owner') return send(403, { error: 'Owner demo role required.' });
          if (req.method === 'GET') return send(200, { merchants: state.merchants });
          if (req.method === 'POST' && text(body.name) && state.merchants.length < 100) {
            const m = {
              id: randomUUID(),
              name: body.name.trim(),
              status: 'active',
              version: 1,
              ceilings: [...PERMISSIONS],
              terminals: ['terminal-web', 'terminal-mobile'],
            };
            state.merchants.push(m);
            log(s, 'demo.merchant.created', m.name, m.id);
            return send(201, { merchant: m });
          }
          return send(400, { error: 'Enter a merchant name (1–80 characters).' });
        }
        const change = url.pathname.match(/^\/api\/merchants\/([^/]+)$/);
        if (change && req.method === 'PATCH') {
          if (s.role !== 'owner') return send(403, { error: 'Owner demo role required.' });
          const m = state.merchants.find((m) => m.id === change[1]);
          if (!m || body.version !== m.version)
            return send(409, { error: 'Record changed. Reload before editing.' });
          if (!['active', 'suspended'].includes(body.status))
            return send(400, { error: 'Invalid status.' });
          if (m.status !== body.status) {
            m.status = body.status;
            m.version++;
            for (const [k, v] of state.sessions)
              if (v.merchantId === m.id) state.sessions.delete(k);
            log(s, 'demo.merchant.' + m.status, m.name, m.id);
          }
          return send(200, { merchant: m });
        }
        const withdraw = url.pathname.match(/^\/api\/merchants\/([^/]+)\/withdraw$/);
        if (withdraw && req.method === 'POST') {
          if (s.role !== 'owner') return send(403, { error: 'Owner demo role required.' });
          const m = state.merchants.find((m) => m.id === withdraw[1]);
          if (!m || body.version !== m.version || !m.ceilings.includes(body.permission))
            return send(409, { error: 'Ceiling changed or already withdrawn.' });
          m.ceilings = m.ceilings.filter((p) => p !== body.permission);
          m.version++;
          for (const u of state.users.filter((u) => u.merchantId === m.id)) {
            u.permissions = u.permissions.filter((p) => p !== body.permission);
            u.version++;
          }
          for (const [k, v] of state.sessions) if (v.merchantId === m.id) state.sessions.delete(k);
          log(s, 'demo.entitlement.withdrawn', body.permission, m.id);
          return send(200, { merchant: m });
        }
        if (url.pathname === '/api/team' && req.method === 'GET') {
          if (s.role !== 'merchant') return send(403, { error: 'Merchant demo role required.' });
          return send(200, {
            users: state.users.filter((u) => u.merchantId === s.merchantId),
            invitations: state.invitations.filter((i) => i.merchantId === s.merchantId),
            ceiling: merchant.ceilings,
            terminals: merchant.terminals,
          });
        }
        if (url.pathname === '/api/invitations' && req.method === 'POST') {
          if (s.role !== 'merchant') return send(403, { error: 'Merchant demo role required.' });
          if (!text(body.name) || state.invitations.length >= 100)
            return send(400, { error: 'Enter a name (1–80 characters).' });
          const invitation = {
            id: randomUUID(),
            name: body.name.trim(),
            merchantId: s.merchantId,
            used: false,
          };
          state.invitations.push(invitation);
          log(s, 'demo.invitation.created', invitation.name, s.merchantId);
          return send(201, { invitation });
        }
        const grant = url.pathname.match(/^\/api\/team\/([^/]+)$/);
        if (grant && req.method === 'PATCH') {
          if (s.role !== 'merchant') return send(403, { error: 'Merchant demo role required.' });
          const u = state.users.find((u) => u.id === grant[1] && u.merchantId === s.merchantId);
          if (!u) return send(404, { error: 'Demo user not found.' });
          if (u.version !== body.version)
            return send(409, { error: 'Record changed. Reload before editing.' });
          if (
            !Array.isArray(body.permissions) ||
            body.permissions.some((p) => !merchant.ceilings.includes(p)) ||
            !Array.isArray(body.terminals) ||
            body.terminals.some((t) => !merchant.terminals.includes(t)) ||
            !['active', 'disabled'].includes(body.status)
          )
            return send(403, {
              error: 'Assignment exceeds merchant ceiling or terminal boundary.',
            });
          u.permissions = [...new Set(body.permissions)];
          u.terminals = [...new Set(body.terminals)];
          u.status = body.status;
          u.version++;
          for (const [k, v] of state.sessions) if (v.userId === u.id) state.sessions.delete(k);
          log(s, 'demo.permissions.changed', u.name, s.merchantId);
          return send(200, { user: u });
        }
        if (url.pathname === '/api/audit' && req.method === 'GET') {
          if (!can('audit.read')) return send(403, { error: 'Audit permission required.' });
          return send(200, {
            events: state.audit
              .filter((e) => s.role === 'owner' || e.merchantId === s.merchantId)
              .slice(0, 100),
          });
        }
        if (url.pathname === '/api/payments' && req.method === 'GET') {
          if (!can('payments.read'))
            return send(403, { error: 'Payment read permission required.' });
          const allowed = [
            'offset',
            'status',
            'currency',
            'terminal',
            'search',
            'from',
            'to',
            'country',
          ];
          if (
            [...url.searchParams.keys()].some((k) => !allowed.includes(k)) ||
            [...url.searchParams.keys()].some((k) => url.searchParams.getAll(k).length !== 1)
          )
            return send(400, { error: 'Invalid filters.' });
          const offset = Number(url.searchParams.get('offset') ?? 0);
          if (!Number.isInteger(offset) || offset < 0 || offset > 10000 || offset % 10 !== 0)
            return send(400, { error: 'Invalid page.' });
          const rows = state.payments
            .filter(visible)
            .filter((p) =>
              ['status', 'currency', 'terminal', 'country'].every(
                (k) => !url.searchParams.get(k) || p[k] === url.searchParams.get(k),
              ),
            )
            .filter(
              (p) =>
                !url.searchParams.get('search') ||
                p.id.includes(url.searchParams.get('search').slice(0, 80)),
            )
            .filter(
              (p) =>
                (!url.searchParams.get('from') ||
                  p.createdAt.slice(0, 10) >= url.searchParams.get('from')) &&
                (!url.searchParams.get('to') ||
                  p.createdAt.slice(0, 10) <= url.searchParams.get('to')),
            )
            .sort((a, b) => b.createdAt.localeCompare(a.createdAt) || a.id.localeCompare(b.id));
          return send(200, {
            payments: rows.slice(offset, offset + 10),
            total: rows.length,
            offset,
            hasMore: offset + 10 < rows.length,
            simulated: true,
          });
        }
        if (url.pathname === '/api/analytics' && req.method === 'GET') {
          if (!can('payments.read'))
            return send(403, { error: 'Payment read permission required.' });
          const rows = state.payments.filter(visible);
          return send(200, {
            counts: Object.fromEntries(
              ['succeeded', 'failed', 'pending'].map((s) => [
                s,
                rows.filter((p) => p.status === s).length,
              ]),
            ),
            currencies: [...new Set(rows.map((p) => p.currency))].map((currency) => ({
              currency,
              succeededMinor: rows
                .filter((p) => p.currency === currency && p.status === 'succeeded')
                .reduce((n, p) => n + p.amountMinor, 0),
            })),
            financeVisible: can('finance.read'),
            simulated: true,
          });
        }
        const payment = url.pathname.match(/^\/api\/payments\/([^/]+)(\/simulate)?$/);
        if (payment) {
          if (!can('payments.read'))
            return send(403, { error: 'Payment read permission required.' });
          const p = state.payments.find((p) => p.id === payment[1] && visible(p));
          if (!p) return send(404, { error: 'Demo payment not found.' });
          if (req.method === 'GET' && !payment[2])
            return send(200, { payment: p, simulated: true });
          if (req.method === 'POST' && payment[2]) {
            if (!can('payments.simulate') || !['succeeded', 'failed'].includes(body.outcome))
              return send(403, { error: 'Simulator permission required.' });
            if (p.status !== 'pending')
              return send(409, { error: 'Final demo payments cannot change.' });
            p.status = body.outcome;
            p.attempts.push({
              sequence: p.attempts.length + 1,
              provider: 'simulator',
              result: body.outcome,
            });
            p.webhooks.push({
              status: 'simulated-delivered',
              attempts: 1,
              destination: 'No network destination; local demonstration only',
            });
            log(s, 'demo.payment.' + body.outcome, p.id, p.merchantId);
            return send(200, { payment: p, simulated: true });
          }
        }
        return send(405, { error: 'Unsupported demo operation.' });
      }
      if (req.method !== 'GET') return send(404, { error: 'Not found.' });
      const files = {
        '/': ['index.html', 'text/html; charset=utf-8'],
        '/app.js': ['app.js', 'text/javascript'],
        '/styles.css': ['styles.css', 'text/css'],
      };
      const file = files[url.pathname];
      if (!file) return send(404, { error: 'Not found.' });
      return send(
        200,
        await readFile(new URL('../public/' + file[0], import.meta.url), 'utf8'),
        file[1],
      );
    })().catch(() => send(400, { error: 'Demo request failed safely.' }));
  });
  server.requestTimeout = 10000;
  server.headersTimeout = 5000;
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', resolve);
  });
  origin = `http://127.0.0.1:${server.address().port}`;
  return { server, origin };
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (Number(process.versions.node.split('.')[0]) !== 24) {
    process.stderr.write('Install Node.js 24 LTS. No scripts or administrator changes required.');
    process.exit(1);
  }
  startPreview()
    .then(({ origin }) =>
      process.stdout.write(
        `VaultX Pay SYNTHETIC Phase 2 Preview\nOpen ${origin}/\nNo database, gateway, real accounts or credentials. Ctrl+C stops and discards demo state.`,
      ),
    )
    .catch(() => {
      process.stderr.write(
        'Could not start local preview. Port 4175 may already be in use. No fallback port or network exposure attempted.',
      );
      process.exitCode = 1;
    });
}
