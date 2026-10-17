#!/usr/bin/env node
// Validates the inline <script> in assets/index.html compiles.
// Uses vm.Script with lineOffset so SyntaxError lines map back to index.html.
import fs from 'node:fs';
import vm from 'node:vm';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const file = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'assets', 'index.html');
const html = fs.readFileSync(file, 'utf8');
const m = html.match(/<script>([\s\S]*?)<\/script>/);
if (!m) { console.error('No inline <script> found'); process.exit(2); }

const scriptStart = html.slice(0, m.index).split('\n').length; // 1-based

try {
  new vm.Script(m[1], { filename: 'assets/index.html', lineOffset: scriptStart });
  console.log(`OK  inline script (${m[1].split('\n').length} lines, starts at index.html:${scriptStart})`);
} catch (e) {
  console.error(`FAIL  ${e.name}: ${e.message}`);
  const line = e.stack?.match(/index\.html:(\d+)/);
  if (line) {
    const n = Number(line[1]);
    console.error(`index.html:${n}  ${String(html.split('\n')[n - 1]).trim()}`);
  }
  process.exit(1);
}
