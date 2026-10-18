import test from 'node:test';
import assert from 'node:assert/strict';
import { qtypeLabel } from '../ui/src/qtype.js';

test('qtypeLabel: common mnemonics', () => {
  assert.equal(qtypeLabel(1), 'A');
  assert.equal(qtypeLabel(28), 'AAAA');
  assert.equal(qtypeLabel(65), 'HTTPS');
  assert.equal(qtypeLabel('16'), 'TXT');
});

test('qtypeLabel: uncommon, invalid and missing values', () => {
  assert.equal(qtypeLabel(99), 'other');
  assert.equal(qtypeLabel(0), 'other');
  assert.equal(qtypeLabel(-1), 'other');
  assert.equal(qtypeLabel(null), '—');
  assert.equal(qtypeLabel(undefined), '—');
  assert.equal(qtypeLabel(''), '—');
});