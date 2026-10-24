import { test } from 'node:test';
import assert from 'node:assert/strict';
import { refresh } from '../src/refresh.js';
import { watchlist, replayFetch, noSleep } from './helpers.js';

const { data } = await refresh({ watchlist, previous: null, fetchJson: replayFetch(), env: {}, sleep: noSleep, now: '2026-10-24T10:00:00Z' });
const node = data.advisories.find((a) => a.id === 'CVE-2026-111497');

test('CVE-2026-111497 nicknames, in order of appearance', () => {
  assert.deepEqual(node.aliases.nicknames, ['Node2Shell', 'Python2Shell', 'HTTP2Shell', 'Broccoli2Shell']);
});

test('Node.js EOL lines 25, 23, 20 and 18 (for 18 and older) are "kein Fix (EOL)"', () => {
  for (const cycle of ['25', '23', '20', '18']) {
    const r = node.runtimes.find((x) => x.product === 'Node.js' && x.cycle === cycle);
    assert.ok(r, `Node.js ${cycle} row`);
    assert.equal(r.fixedIn, null);
    assert.equal(r.status, 'kein Fix (EOL)');
    assert.match(String(r.eol), /^\d{4}-\d{2}-\d{2}$/);
  }
});

test('exploitation and exposure-path rows stay empty until editorially approved', () => {
  for (const a of data.advisories) {
    assert.deepEqual(a.exploitation, []);
    assert.equal(a.affected.filter((x) => x.role === 'exposure_path').length, 0);
  }
});

test('no hand override touches Debian 13 brotli; OSV value is used', () => {
  for (const cve of watchlist.advisories) assert.equal(cve.fixStatusOverrides.filter((o) => o.ecosystem === 'Debian').length, 0);
  const deb13 = node.affected.find((a) => a.ecosystem === 'Debian' && a.release === '13' && a.package === 'brotli');
  assert.equal(deb13.source, 'osv');
  assert.equal(deb13.override, undefined);
});
