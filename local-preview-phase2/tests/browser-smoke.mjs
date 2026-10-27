/* global URL, document, innerWidth */
import process from 'node:process';
// CI-only tool dependency, supplied outside the standalone runtime package.
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import path from 'node:path';
import { startPreview } from '../scripts/server.mjs';
if (!process.env.VAULTX_PREVIEW_BROWSER_TOOLS)
  throw new Error('Set externally installed Playwright tools directory.');
const { chromium } = createRequire(
  path.join(process.env.VAULTX_PREVIEW_BROWSER_TOOLS, 'package.json'),
)('playwright');
const { server, origin } = await startPreview({ port: 0 });
let browser;
try {
  browser = await chromium.launch({
    headless: true,
    ...(process.env.VAULTX_CHROMIUM_EXECUTABLE
      ? { executablePath: process.env.VAULTX_CHROMIUM_EXECUTABLE }
      : {}),
    ...(process.platform === 'linux' ? { args: ['--no-sandbox'] } : {}),
  });
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
  const page = await context.newPage();
  const errors = [],
    external = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await context.route('**/*', (route) => {
    if (new URL(route.request().url()).origin !== origin) {
      external.push(route.request().url());
      return route.abort();
    }
    return route.continue();
  });
  const heading = (name) => page.getByRole('heading', { name, exact: true }).waitFor();
  const click = (name) => page.getByRole('button', { name, exact: true }).click();
  await page.goto(origin);
  await heading('Choose a demonstration workspace');
  await click('Open demo owner');
  await heading('Owner overview');
  for (const [nav, title] of [
    ['Merchant directory', 'Merchant directory'],
    ['Client accounts', 'Client accounts'],
    ['Security policies', 'Platform security policies'],
    ['Audit activity', 'Audit activity'],
  ]) {
    await click(nav);
    await heading(title);
  }
  await click('Merchant directory');
  await page.getByLabel('New synthetic merchant name').fill('Aurora Browser · Demo');
  await click('Create demo merchant');
  await page.getByRole('cell', { name: 'Aurora Browser · Demo', exact: true }).waitFor();
  await click('Switch demo account');
  await heading('Choose a demonstration workspace');
  await page
    .getByLabel('Demo merchant organization')
    .selectOption({ label: 'Northstar Commerce · Demo' });
  await click('Open demo merchant');
  await heading('Merchant overview');
  await click('Team & permissions');
  await heading('Team & permissions');
  await page.getByLabel('New submerchant user').fill('Taylor Browser · Demo');
  await click('Create demo invitation');
  await page.getByRole('cell', { name: 'Taylor Browser · Demo', exact: true }).waitFor();
  await click('Switch demo account');
  await heading('Choose a demonstration workspace');
  await click('Activate Taylor Browser · Demo');
  await page
    .getByLabel('Demo submerchant user')
    .getByRole('option', { name: 'Taylor Browser · Demo' })
    .waitFor({ state: 'attached' });
  await page
    .getByLabel('Demo merchant organization')
    .selectOption({ label: 'Northstar Commerce · Demo' });
  await click('Open demo merchant');
  await heading('Merchant overview');
  await click('Team & permissions');
  await heading('Team & permissions');
  const panel = page
    .locator('section')
    .filter({ has: page.getByRole('heading', { name: 'Taylor Browser · Demo', exact: true }) });
  for (const permission of [
    'payments.read',
    'payments.simulate',
    'finance.read',
    'audit.read',
    'terminal-web',
  ])
    await panel.getByLabel(permission, { exact: true }).check();
  await panel
    .getByRole('button', { name: 'Save assignments for Taylor Browser · Demo', exact: true })
    .click();
  await page.getByRole('status').filter({ hasText: 'Demo assignment saved' }).waitFor();
  await click('Terminal access');
  await heading('Terminal access');
  await click('Account settings');
  await heading('Account settings');
  await click('Switch demo account');
  await heading('Choose a demonstration workspace');
  await page.getByLabel('Demo submerchant user').selectOption({ label: 'Taylor Browser · Demo' });
  await click('Open demo submerchant');
  await heading('Submerchant PSP overview');
  await click('Transactions');
  await heading('Transaction monitoring');
  await click('Next page');
  await page.getByText(/offset 10/).waitFor();
  await click('Previous page');
  await page.getByText(/offset 0/).waitFor();
  await page.getByLabel('Payment status', { exact: true }).selectOption('pending');
  await click('Apply filters');
  await page.waitForFunction(() => {
    const rows = [...document.querySelectorAll('tbody tr')];
    return rows.length > 0 && rows.every((r) => r.children[2]?.textContent === 'pending');
  });
  await page
    .getByRole('button', { name: /^Investigate / })
    .first()
    .click();
  await heading('Transaction investigation');
  await click('Simulate success');
  await page.getByText('succeeded', { exact: true }).first().waitFor();
  await page.getByText('simulated-delivered', { exact: true }).waitFor();
  await click('Audit activity');
  await heading('Audit activity');
  await page.getByRole('cell', { name: 'demo.payment.succeeded', exact: true }).waitFor();
  await click('Finance & settlement');
  await heading('Finance & settlement');
  await page.setViewportSize({ width: 390, height: 844 });
  await click('PSP overview');
  await heading('Submerchant PSP overview');
  assert.ok(await page.locator('body').evaluate((e) => e.scrollWidth <= innerWidth));
  // Independently change the signed-in user's permissions via synthetic merchant cookie.
  const other = await browser.newContext();
  const m = await other.request.post(origin + '/demo/login', {
    headers: { Origin: origin },
    data: { role: 'merchant', merchantId: 'merchant-north' },
  });
  assert.equal(m.status(), 200);
  const me = await (await other.request.get(origin + '/api/me')).json();
  const team = await (await other.request.get(origin + '/api/team')).json();
  const user = team.users.find((u) => u.name === 'Taylor Browser · Demo');
  const changed = await other.request.patch(origin + '/api/team/' + user.id, {
    headers: { Origin: origin, 'X-Demo-CSRF': me.csrf },
    data: { version: user.version, permissions: [], terminals: [], status: 'disabled' },
  });
  assert.equal(changed.status(), 200);
  await click('Transactions');
  await heading('Choose a demonstration workspace');
  assert.equal(
    await page.getByRole('heading', { name: 'Transaction monitoring', exact: true }).count(),
    0,
  );
  await other.close();
  assert.deepEqual(errors, []);
  assert.deepEqual(external, []);
  process.stdout.write(
    'PASS: owner/merchant/submerchant screens, invitation activation, bounded assignment, payments, simulator audit, session revocation, mobile and no external network.',
  );
} finally {
  if (browser) await browser.close();
  await new Promise((resolve) => server.close(resolve));
}
