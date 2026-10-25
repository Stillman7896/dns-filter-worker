// Capture README screenshots from the dev server (ui/mock/api.js answers /api/*).
// Usage: npm run ui:dev          (in another shell)
//        node tools/screenshots.js [--base http://127.0.0.1:5173] [--out docs/img]
import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import { chromium } from 'playwright';

const args = process.argv.slice(2);
const arg = (name, fallback) => {
  const i = args.indexOf(`--${name}`);
  return i === -1 ? fallback : args[i + 1];
};

const base = arg('base', 'http://127.0.0.1:5173');
const out = path.resolve(arg('out', 'docs/img'));
const password = process.env.DEMO_PASSWORD || 'demo';

const VIEWS = ['overview', 'rules', 'lists', 'logs', 'settings', 'probe', 'backup'];
const DESKTOP = { width: 1440, height: 900 };
const MOBILE = { width: 390, height: 844 };

async function signIn(page) {
  await page.goto(`${base}/dashboard`, { waitUntil: 'networkidle' });
  const field = page.locator('#pw');
  if (await field.isVisible().catch(() => false)) {
    await field.fill(password);
    await page.getByRole('button', { name: 'Sign in' }).click();
  }
  // "Sign out" only renders once the dashboard is authenticated and loaded.
  await page.waitForFunction(() => document.body.innerText.includes('Sign out'), null, { timeout: 20000 });
}

async function shoot(page, file) {
  await page.waitForLoadState('networkidle');
  await page.evaluate(() => document.fonts.ready);
  await page.waitForTimeout(250);
  await page.screenshot({ path: path.join(out, file) });
  console.log('wrote', file);
}

await mkdir(out, { recursive: true });
const browser = await chromium.launch();

for (const theme of ['light', 'dark']) {
  const context = await browser.newContext({ viewport: DESKTOP, deviceScaleFactor: 2 });
  await context.addInitScript((mode) => localStorage.setItem('dns-dash-theme', mode), theme);
  const page = await context.newPage();
  await signIn(page);
  const views = theme === 'light' ? VIEWS : ['overview'];
  for (const view of views) {
    await page.goto(`${base}/dashboard#/${view}`, { waitUntil: 'networkidle' });
    await shoot(page, `${view}${theme === 'dark' ? '-dark' : ''}.png`);
  }
  await context.close();
}

for (const [file, view] of [['mobile-logs.png', 'logs'], ['mobile-overview.png', 'overview']]) {
  const context = await browser.newContext({
    viewport: MOBILE,
    deviceScaleFactor: 3,
    isMobile: true,
    hasTouch: true,
  });
  await context.addInitScript(() => localStorage.setItem('dns-dash-theme', 'light'));
  const page = await context.newPage();
  await signIn(page);
  await page.goto(`${base}/dashboard#/${view}`, { waitUntil: 'networkidle' });
  await shoot(page, file);
  await context.close();
}

await browser.close();
