// Render brand raster assets (GitHub social preview, apple touch icon) from HTML,
// so the brand typeface is baked in. Requires the Playwright chromium build:
//   npx playwright install chromium && node tools/render-brand.js
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { chromium } from 'playwright';

const root = path.resolve(import.meta.dirname, '..');
const mark = await readFile(path.join(root, 'brand/mark.svg'), 'utf8');
// Inlined as a data URI: a file:// subresource is blocked from a setContent page.
const shot = `data:image/png;base64,${(await readFile(path.join(root, 'docs/img/overview.png'))).toString('base64')}`;

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1280, height: 640 }, deviceScaleFactor: 1 });

await page.setContent(`<!doctype html><html><head><meta charset="utf-8">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Instrument+Sans:wght@400;600&family=IBM+Plex+Mono:wght@400;500&display=swap">
<style>
  * { margin: 0; box-sizing: border-box; }
  body { width: 1280px; height: 640px; overflow: hidden; background: #0B1018;
         font-family: 'Instrument Sans', system-ui, sans-serif; position: relative; }
  .glow { position: absolute; width: 980px; height: 980px; left: -300px; top: -460px; border-radius: 50%;
          background: radial-gradient(circle, rgba(255,176,46,.15), rgba(255,176,46,0) 62%); }
  .wrap { position: relative; display: flex; align-items: center; gap: 48px; height: 100%; padding: 0 56px; }
  .text { width: 470px; flex: none; }
  .lock { display: flex; align-items: center; gap: 20px; }
  .lock svg { width: 68px; height: 68px; flex: none; }
  h1 { color: #F4F7FB; font-size: 70px; font-weight: 600; letter-spacing: -2.2px; line-height: 1; }
  .kicker { margin-top: 26px; color: #FFB02E; font-family: 'IBM Plex Mono', monospace; font-size: 13px;
            letter-spacing: 2.1px; text-transform: uppercase; }
  p { margin-top: 14px; color: #93A1B5; font-size: 19px; line-height: 1.5; max-width: 430px; }
  .card { width: 650px; height: 448px; flex: none; border-radius: 16px; overflow: hidden;
          border: 1px solid rgba(255,255,255,.09); background: #131A25;
          box-shadow: 0 40px 80px -30px rgba(0,0,0,.9); }
  /* The dashboard screenshot at 1x logical scale, cropped to its content column. */
  .card img { width: 1440px; display: block; margin: -60px 0 0 -224px; }
</style></head>
<body>
  <div class="glow"></div>
  <div class="wrap">
    <div class="text">
      <div class="lock">${mark}<h1>Sinkker</h1></div>
      <div class="kicker">DNS sinkhole on Cloudflare Workers</div>
      <p>Network-wide ad, tracker and malware blocking — with a dashboard, no server to run.</p>
    </div>
    <div class="card"><img src="${shot}" alt=""></div>
  </div>
</body></html>`);

await page.evaluate(() => document.fonts.ready);
await page.waitForTimeout(400);
await page.screenshot({ path: path.join(root, 'brand/social-preview.png') });
console.log('wrote brand/social-preview.png');

await page.setViewportSize({ width: 180, height: 180 });
await page.setContent(`<!doctype html><html><head><meta charset="utf-8"><style>
  body { margin: 0; width: 180px; height: 180px; background: #0B1018; display: grid; place-items: center; }
  svg { width: 128px; height: 128px; }
</style></head><body>${mark}</body></html>`);
await page.screenshot({ path: path.join(root, 'ui/public/apple-touch-icon.png') });
console.log('wrote ui/public/apple-touch-icon.png');

await browser.close();
