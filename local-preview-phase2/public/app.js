/* global document, fetch, AbortSignal, URLSearchParams, window */
// Synthetic UI only. Never receives production credentials or calls the gateway.
const main = document.querySelector('#content');
let identity = null,
  screen = 'overview',
  selectedPayment = null,
  offset = 0,
  filter = {},
  epoch = 0;
const make = (tag, content, attrs = {}) => {
  const e = document.createElement(tag);
  if (content !== undefined) e.textContent = content;
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
  return e;
};
const add = (e, ...children) => {
  children
    .flat()
    .filter(Boolean)
    .forEach((c) => e.append(c));
  return e;
};
const button = (label, action, attrs) => {
  const e = make('button', label, attrs);
  e.addEventListener('click', () => void run(action));
  return e;
};
const select = (label, values, value) => {
  const e = make('select', undefined, { 'aria-label': label });
  values.forEach(([v, t]) => {
    const o = make('option', t, { value: v });
    o.selected = v === value;
    e.append(o);
  });
  return e;
};
const field = (label, input) => add(make('label', label), input);
const message = (value) => {
  document.querySelector('#message').textContent = value;
};
async function api(path, method = 'GET', body) {
  const headers = {};
  if (method !== 'GET') {
    headers['Content-Type'] = 'application/json';
    if (identity) headers['X-Demo-CSRF'] = identity.csrf;
  }
  const response = await fetch(path, {
    method,
    headers,
    ...(body ? { body: JSON.stringify(body) } : {}),
    credentials: 'same-origin',
    cache: 'no-store',
    redirect: 'error',
    signal: AbortSignal.timeout(8000),
  });
  const data = await response.json();
  if (!response.ok) {
    if (response.status === 401) {
      identity = null;
      epoch++;
      main.replaceChildren();
      document.querySelector('#identity').textContent = 'Demo session invalidated';
      await login();
    }
    throw new Error(data.error || 'Demo request could not be completed.');
  }
  return data;
}
async function run(action) {
  try {
    await action();
  } catch (error) {
    message(
      error.name === 'TimeoutError'
        ? 'Local request timed out. No automatic retry.'
        : error instanceof Error
          ? error.message
          : 'Demo action failed.',
    );
  }
}
function title(t, description) {
  main.append(make('h1', t), make('p', description));
}
const badge = (text) => make('span', text, { class: 'badge ' + text });
const money = (minor, currency) =>
  new Intl.NumberFormat(undefined, { style: 'currency', currency }).format(minor / 100);
function table(headers, rows) {
  const table = make('table'),
    head = make('thead'),
    body = make('tbody');
  head.append(
    add(
      make('tr'),
      headers.map((t) => make('th', t, { scope: 'col' })),
    ),
  );
  rows.forEach((cells) =>
    body.append(
      add(
        make('tr'),
        cells.map((c) =>
          add(
            make('td'),
            typeof c === 'string' || typeof c === 'number' ? document.createTextNode(String(c)) : c,
          ),
        ),
      ),
    ),
  );
  table.append(head, body);
  return add(make('div', undefined, { class: 'scroll panel' }), table);
}
const can = (p) => identity?.permissions.includes(p);
function navigation() {
  const nav = document.querySelector('#navigation');
  nav.replaceChildren();
  const items =
    identity.role === 'owner'
      ? [
          ['overview', 'Owner overview'],
          ['merchants', 'Merchant directory'],
          ['clients', 'Client accounts'],
          ['security', 'Security policies'],
          ['audit', 'Audit activity'],
        ]
      : identity.role === 'merchant'
        ? [
            ['overview', 'Merchant overview'],
            ['team', 'Team & permissions'],
            ['terminals', 'Terminal access'],
            ['payments', 'Transactions'],
            ['audit', 'Audit activity'],
            ['settings', 'Account settings'],
          ]
        : [
            ['overview', 'PSP overview'],
            ['payments', 'Transactions'],
            ['finance', 'Finance & settlement'],
            ['audit', 'Audit activity'],
          ];
  items.forEach(([key, label]) =>
    nav.append(
      button(
        label,
        async () => {
          screen = key;
          offset = 0;
          await render();
        },
        key === screen ? { 'aria-current': 'page' } : {},
      ),
    ),
  );
}
async function login() {
  const ticket = ++epoch;
  const catalog = await api('/demo/catalog');
  if (ticket !== epoch) return;
  identity = null;
  main.replaceChildren();
  document.querySelector('#navigation').replaceChildren();
  title(
    'Choose a demonstration workspace',
    'Three distinct access levels. Never enter a real username, password or credential. Synthetic activation delivers no email.',
  );
  const grid = make('div', undefined, { class: 'grid login' });
  const owner = add(
    make('section', undefined, { class: 'card' }),
    make('h2', 'Platform owner'),
    make(
      'p',
      'Create merchants, suspend organizations and inspect global demonstration audit. MFA is not implemented in this isolated preview.',
    ),
    button('Open demo owner', () => signIn({ role: 'owner' })),
  );
  const merchantSelect = select(
    'Demo merchant organization',
    catalog.merchants.map((m) => [m.id, m.name]),
  );
  const merchant = add(
    make('section', undefined, { class: 'card' }),
    make('h2', 'Merchant administrator'),
    make('p', 'Invite submerchant users and assign bounded permissions within this organization.'),
    merchantSelect,
    button('Open demo merchant', () =>
      signIn({ role: 'merchant', merchantId: merchantSelect.value }),
    ),
  );
  const userSelect = select(
    'Demo submerchant user',
    catalog.users.map((u) => [u.id, u.name]),
  );
  const sub = add(
    make('section', undefined, { class: 'card' }),
    make('h2', 'Submerchant PSP user'),
    make(
      'p',
      'Transactions and simulator actions are restricted to assigned terminals and permissions.',
    ),
    userSelect,
    button('Open demo submerchant', () =>
      signIn({ role: 'submerchant', userId: userSelect.value }),
    ),
  );
  grid.append(owner, merchant, sub);
  main.append(grid);
  if (catalog.invitations.length) {
    const panel = add(
      make('section', undefined, { class: 'panel' }),
      make('h2', 'Activate a synthetic invitation'),
      make(
        'p',
        'Demo-only activation. No email, password, token delivery or production enrollment is represented.',
      ),
    );
    for (const i of catalog.invitations)
      panel.append(
        button('Activate ' + i.name, async () => {
          await api('/demo/activate', 'POST', { invitationId: i.id });
          message('Synthetic account activated. Merchant administrator must assign permissions.');
          await login();
        }),
      );
    main.append(panel);
  }
}
async function signIn(body) {
  await api('/demo/login', 'POST', body);
  identity = await api('/api/me');
  screen = 'overview';
  filter = {};
  offset = 0;
  epoch++;
  await render();
}
document.querySelector('#switch').addEventListener(
  'click',
  () =>
    void run(async () => {
      if (identity) await api('/api/logout', 'POST');
      identity = null;
      document.querySelector('#identity').textContent = 'Choose a synthetic account';
      await login();
    }),
);
async function render() {
  const ticket = ++epoch;
  if (!identity) return login();
  main.replaceChildren(make('p', 'Loading local demo…'));
  const current = await api('/api/me');
  if (ticket !== epoch) return;
  identity = current;
  main.replaceChildren();
  message('');
  document.querySelector('#identity').textContent =
    identity.name + ' · ' + identity.role.toUpperCase() + ' · SIMULATED';
  navigation();
  if (['overview', 'merchants', 'clients'].includes(screen) && identity.role === 'owner') {
    const { merchants } = await api('/api/merchants');
    if (ticket !== epoch) return;
    title(
      screen === 'overview'
        ? 'Owner overview'
        : screen === 'clients'
          ? 'Client accounts'
          : 'Merchant directory',
      'Platform-wide synthetic management. Changes affect disposable memory only.',
    );
    const cards = make('div', undefined, { class: 'grid' });
    for (const [label, value] of [
      ['Demo merchants', merchants.length],
      ['Active organizations', merchants.filter((m) => m.status === 'active').length],
      ['Real payments', 0],
    ])
      cards.append(
        add(
          make('section', undefined, { class: 'card' }),
          make('p', label),
          make('div', String(value), { class: 'metric' }),
        ),
      );
    main.append(cards);
    const name = make('input', undefined, {
      placeholder: 'Example: Aurora Retail · Demo',
      maxlength: '80',
      required: '',
    });
    const create = add(
      make('form', undefined, { class: 'row' }),
      field('New synthetic merchant name', name),
      make('button', 'Create demo merchant', { type: 'submit' }),
    );
    create.addEventListener('submit', (e) => {
      e.preventDefault();
      void run(async () => {
        await api('/api/merchants', 'POST', { name: name.value });
        message('Demo merchant created. Switch to its merchant workspace to invite users.');
        await render();
      });
    });
    main.append(create);
    main.append(
      table(
        ['Merchant', 'State', 'Revision', 'Demo actions'],
        merchants.map((m) => [
          m.name,
          badge(m.status),
          m.version,
          add(
            make('div', undefined, { class: 'actions' }),
            button(m.status === 'active' ? 'Suspend' : 'Reactivate', async () => {
              await api('/api/merchants/' + m.id, 'PATCH', {
                version: m.version,
                status: m.status === 'active' ? 'suspended' : 'active',
              });
              await render();
            }),
            m.ceilings.includes('payments.read') &&
              button('Withdraw payment read', async () => {
                await api('/api/merchants/' + m.id + '/withdraw', 'POST', {
                  version: m.version,
                  permission: 'payments.read',
                });
                await render();
              }),
          ),
        ]),
      ),
    );
  } else if (screen === 'overview') {
    title(
      identity.role === 'merchant' ? 'Merchant overview' : 'Submerchant PSP overview',
      'Synthetic transaction analytics restricted to the current organization and assigned terminals. Currencies are never added together.',
    );
    if (!can('payments.read'))
      main.append(
        make('p', 'Payment analytics unavailable: client permission has not been granted.'),
      );
    else {
      const a = await api('/api/analytics');
      if (ticket !== epoch) return;
      const grid = make('div', undefined, { class: 'grid' });
      const total = Object.values(a.counts).reduce((a, b) => a + b, 0);
      const metrics = [
        ['Visible transactions', total],
        ['Succeeded', a.counts.succeeded],
        ['Pending', a.counts.pending],
        ['Success rate', total ? Math.round((a.counts.succeeded / total) * 100) + '%' : '—'],
      ];
      for (const [label, value] of metrics)
        grid.append(
          add(
            make('section', undefined, { class: 'card' }),
            make('p', label),
            make('div', String(value), { class: 'metric' }),
          ),
        );
      main.append(grid);
      main.append(
        table(
          ['Currency', 'Synthetic succeeded deposits'],
          a.currencies.map((c) => [c.currency, money(c.succeededMinor, c.currency)]),
        ),
      );
    }
    main.append(
      add(
        make('div', undefined, { class: 'notice' }),
        make(
          'p',
          'Withdrawals, refunds, real cascading and settlement accounting are not implemented. No invented ledger balances are presented. All activity here is a simulator demonstration.',
        ),
      ),
    );
  } else if (screen === 'team') {
    const data = await api('/api/team');
    if (ticket !== epoch) return;
    title(
      'Team & permissions',
      'Invite synthetic submerchant users. Assignments cannot exceed this merchant’s permission ceiling or terminals. Any permission change invalidates the user’s current demo sessions.',
    );
    const name = make('input', undefined, {
      placeholder: 'Demo user display name',
      maxlength: '80',
      required: '',
    });
    const invite = add(
      make('form', undefined, { class: 'row' }),
      field('New submerchant user', name),
      make('button', 'Create demo invitation', { type: 'submit' }),
    );
    invite.addEventListener('submit', (e) => {
      e.preventDefault();
      void run(async () => {
        await api('/api/invitations', 'POST', { name: name.value });
        await render();
        message('Invitation created. Switch demo account to activate it.');
      });
    });
    main.append(invite);
    for (const u of data.users) {
      const panel = add(
        make('section', undefined, { class: 'panel' }),
        make('h2', u.name),
        make('p', 'Synthetic submerchant user · revision ' + u.version),
      );
      const permissions = make('div', undefined, { class: 'checks' });
      data.ceiling.forEach((p) => {
        const c = make('input', undefined, { type: 'checkbox', value: p });
        c.checked = u.permissions.includes(p);
        permissions.append(field(p, c));
      });
      const terminals = make('div', undefined, { class: 'checks' });
      data.terminals.forEach((t) => {
        const c = make('input', undefined, { type: 'checkbox', value: t });
        c.checked = u.terminals.includes(t);
        terminals.append(field(t, c));
      });
      const status = select(
        'Account state for ' + u.name,
        [
          ['active', 'Active'],
          ['disabled', 'Disabled'],
        ],
        u.status,
      );
      panel.append(
        make('h3', 'Explicit permissions'),
        permissions,
        make('h3', 'Terminal boundary'),
        terminals,
        field('Account state', status),
        button('Save assignments for ' + u.name, async () => {
          await api('/api/team/' + u.id, 'PATCH', {
            version: u.version,
            permissions: [...permissions.querySelectorAll(':checked')].map((c) => c.value),
            terminals: [...terminals.querySelectorAll(':checked')].map((c) => c.value),
            status: status.value,
          });
          await render();
          message('Demo assignment saved; previous user sessions invalidated.');
        }),
      );
      main.append(panel);
    }
    main.append(
      table(
        ['Invitation', 'State'],
        data.invitations.map((i) => [
          i.name,
          i.used ? 'Activated' : 'Awaiting synthetic activation',
        ]),
      ),
    );
  } else if (screen === 'terminals') {
    const data = await api('/api/team');
    if (ticket !== epoch) return;
    title(
      'Terminal access',
      'Terminals are synthetic scopes, not payment provider connections. Edit individual access in Team & permissions.',
    );
    main.append(
      table(
        ['Terminal', 'Assigned users'],
        data.terminals.map((t) => [
          t,
          data.users
            .filter((u) => u.terminals.includes(t))
            .map((u) => u.name)
            .join(', ') || 'None',
        ]),
      ),
    );
  } else if (screen === 'payments') {
    title(
      'Transaction monitoring',
      'Search and filter synthetic transactions. Ten results per page, deterministic ordering and server-side tenant/terminal scope.',
    );
    if (!can('payments.read')) {
      main.append(make('p', 'Payment read permission required.'));
      return;
    }
    const controls = make('form', undefined, { class: 'row' });
    const search = make('input', undefined, {
      placeholder: 'demo-payment-002',
      value: filter.search ?? '',
    });
    const status = select(
      'Payment status',
      [
        ['', 'All statuses'],
        ['pending', 'Pending'],
        ['succeeded', 'Succeeded'],
        ['failed', 'Failed'],
      ],
      filter.status,
    );
    const currency = select(
      'Currency',
      [
        ['', 'All currencies'],
        ['EUR', 'EUR'],
        ['USD', 'USD'],
      ],
      filter.currency,
    );
    const from = make('input', undefined, { type: 'date', value: filter.from ?? '' });
    const to = make('input', undefined, { type: 'date', value: filter.to ?? '' });
    controls.append(
      field('Payment ID search', search),
      field('Status', status),
      field('Currency', currency),
      field('From', from),
      field('To', to),
      make('button', 'Apply filters', { type: 'submit' }),
    );
    controls.addEventListener('submit', (e) => {
      e.preventDefault();
      filter = {
        search: search.value,
        status: status.value,
        currency: currency.value,
        from: from.value,
        to: to.value,
      };
      offset = 0;
      void run(render);
    });
    main.append(controls);
    const query = new URLSearchParams({ ...filter, offset: String(offset) });
    const data = await api('/api/payments?' + query);
    if (ticket !== epoch) return;
    main.append(
      table(
        ['Payment', 'Amount', 'Status', 'Terminal', 'Country', 'Date', ''],
        data.payments.map((p) => [
          p.id,
          money(p.amountMinor, p.currency),
          badge(p.status),
          p.terminal,
          p.country,
          new Date(p.createdAt).toLocaleDateString(),
          button('Investigate ' + p.id, async () => {
            selectedPayment = p.id;
            screen = 'detail';
            await render();
          }),
        ]),
      ),
    );
    const prev = button('Previous page', async () => {
      offset -= 10;
      await render();
    });
    prev.disabled = offset === 0;
    const next = button('Next page', async () => {
      offset += 10;
      await render();
    });
    next.disabled = !data.hasMore;
    main.append(
      add(
        make('div', undefined, { class: 'row' }),
        prev,
        make('p', `${data.total} matching demo payments · offset ${offset}`),
        next,
      ),
    );
  } else if (screen === 'detail') {
    const { payment: p } = await api('/api/payments/' + encodeURIComponent(selectedPayment));
    if (ticket !== epoch) return;
    title('Transaction investigation', p.id + ' · SIMULATOR ONLY');
    const panel = add(
      make('section', undefined, { class: 'panel' }),
      make('h2', money(p.amountMinor, p.currency)),
      badge(p.status),
      make('p', p.terminal + ' · ' + p.country + ' · ' + p.method),
      make('p', 'No real card details or provider credentials exist.'),
    );
    if (p.status === 'pending' && can('payments.simulate'))
      panel.append(
        add(
          make('div', undefined, { class: 'actions' }),
          button('Simulate success', async () => {
            await api('/api/payments/' + p.id + '/simulate', 'POST', { outcome: 'succeeded' });
            await render();
          }),
          button('Simulate failure', async () => {
            await api('/api/payments/' + p.id + '/simulate', 'POST', { outcome: 'failed' });
            await render();
          }),
        ),
      );
    else if (p.status === 'pending')
      panel.append(
        make('p', 'Simulator actions restricted: payments.simulate permission required.'),
      );
    main.append(
      panel,
      make('h2', 'Payment attempts · synthetic'),
      table(
        ['Attempt', 'Provider', 'Result'],
        p.attempts.map((a) => [a.sequence, a.provider, a.result]),
      ),
      make('h2', 'Webhook visibility · synthetic'),
      p.webhooks.length
        ? table(
            ['Outcome', 'Attempts', 'Destination'],
            p.webhooks.map((w) => [w.status, w.attempts, w.destination]),
          )
        : make('p', 'No local simulated webhook yet. No network delivery occurs.'),
      button('Back to transactions', async () => {
        screen = 'payments';
        await render();
      }),
    );
  } else if (screen === 'audit') {
    title(
      'Audit activity',
      'Immutable within the disposable runtime. Resetting or stopping the demo discards all events. Production audit durability is not represented.',
    );
    const { events } = await api('/api/audit');
    if (ticket !== epoch) return;
    main.append(
      table(
        ['When', 'Actor', 'Action', 'Target'],
        events.map((e) => [new Date(e.occurredAt).toLocaleString(), e.actor, e.action, e.target]),
      ),
    );
  } else if (screen === 'finance') {
    title(
      'Finance & settlement',
      'Permission-aware synthetic finance overview. No real balance, withdrawal, refund or settlement ledger exists.',
    );
    if (!can('finance.read')) main.append(make('p', 'Finance read permission required.'));
    else {
      const a = await api('/api/analytics');
      if (ticket !== epoch) return;
      main.append(
        table(
          ['Currency', 'Succeeded synthetic deposits'],
          a.currencies.map((c) => [c.currency, money(c.succeededMinor, c.currency)]),
        ),
        make(
          'p',
          'Balances and settlement: unavailable — no ledger implemented. No funds can be withdrawn.',
        ),
      );
    }
  } else if (screen === 'security') {
    title(
      'Platform security policies',
      'Demonstration of security boundaries, not production configuration controls.',
    );
    main.append(
      add(
        make('section', undefined, { class: 'panel' }),
        make('h2', 'Enforced in this isolated demo'),
        make(
          'p',
          'Owner and merchant role boundaries · tenant and terminal predicates · assignment ceiling · session invalidation · local Origin and CSRF checks · optimistic revision checks.',
        ),
        make('h2', 'Explicitly not represented'),
        make(
          'p',
          'Real MFA, password hashing, invitation email delivery, production enrollment/recovery, database audit durability and owner authentication. No security gate is enabled.',
        ),
      ),
    );
  } else {
    title('Account settings', 'Read-only synthetic organization settings.');
    main.append(
      make('p', 'Organization: ' + identity.name),
      make('p', 'Mode: simulator · storage: disposable memory · real credentials: none'),
    );
  }
  if (ticket !== epoch) return;
  main.append(
    add(
      make('div', undefined, { class: 'actions' }),
      button(
        'Reset disposable demo state',
        async () => {
          await api('/demo/reset', 'POST');
          identity = null;
          document.querySelector('#identity').textContent = 'Demo reset';
          await login();
        },
        { class: 'danger' },
      ),
    ),
  );
}
window.addEventListener('pageshow', () => {
  if (identity) void run(render);
});
document.addEventListener('visibilitychange', () => {
  if (!document.hidden && identity) void run(render);
});
void run(login);
