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

test('exploitation entries carry date, kind and source, but no unapproved note text', () => {
  assert.deepEqual(node.exploitation.map((e) => [e.date, e.kind, e.sourceLabel]), [
    ['2026-10-22', 'poc_public', 'Aikido'],
    ['2026-10-22', 'rce_lab', 'Imperva'],
    ['2026-10-24', 'none_reported', 'Strobes'],
  ]);
  for (const a of data.advisories) for (const e of a.exploitation) assert.equal(e.note, undefined);
});

test('Express 5 / body-parser is an exposure path, not a bug carrier', () => {
  const bp = node.affected.find((a) => a.package === 'body-parser');
  assert.equal(bp.ecosystem, 'npm');
  assert.equal(bp.role, 'exposure_path');
  assert.equal(bp.fixStatus, 'none');
  assert.equal(bp.source, 'watchlist');
});

test('PyPI rows get display names; library row gets the backport note', () => {
  const py = Object.fromEntries(node.affected.filter((a) => a.ecosystem === 'PyPI').map((a) => [a.package, a]));
  assert.equal(py.brotli.displayName, 'Python Brotli');
  assert.equal(py.brotlicffi.displayName, 'Python brotlicffi');
  assert.equal(py.brotli.fixStatus, 'fixed', 'annotation does not touch fixStatus');
  assert.match(node.affected.find((a) => a.ecosystem === 'library').note, /Backport/);
});

test('credits use real names and include the research credits', () => {
  const names = node.credits.map((c) => c.name);
  assert.ok(names.includes('Matteo Collina, Antoine du Hamel'));
  assert.ok(!names.some((n) => /mcollina|aduh95/.test(n)));
  for (const n of ['Imperva Red Team', 'OpenSourceMalware', 'Aikido']) assert.ok(names.includes(n), n);
});

test('published is the earliest timestamp across OSV and NVD, with its source', () => {
  assert.equal(node.published, '2026-10-22T13:35:41Z');
  assert.equal(node.publishedSource, 'osv');
  const php = data.advisories.find((a) => a.id === 'CVE-2026-109618');
  assert.equal(php.publishedSource, 'nvd', 'no OSV record for PHP2Shell');
});

test('per-advisory sources include endoflife and vendor where used', () => {
  assert.equal(node.sources.endoflife.status, 'ok');
  assert.equal(node.sources.vendor.status, 'ok');
  const php = data.advisories.find((a) => a.id === 'CVE-2026-109618');
  assert.equal(php.sources.endoflife.status, 'ok');
  assert.equal(php.sources.vendor, undefined, 'no fixRef PR for PHP2Shell');
});

test('weak reference labels are improved and dates filled where the source gives one', () => {
  const byUrl = Object.fromEntries(data.advisories.flatMap((a) => a.references).map((r) => [r.url, r]));
  assert.equal(byUrl['http://www.openwall.com/lists/oss-security/2026/10/23/25'].label, 'oss-security · 23.10.2026 · Nachricht 25');
  assert.equal(byUrl['http://www.openwall.com/lists/oss-security/2026/10/23/25'].date, '2026-10-23');
  assert.equal(byUrl['https://github.com/google/brotli'].label, 'GitHub · google/brotli');
  assert.equal(byUrl['https://github.com/CVEProject/cvelistV5/tree/main/cves/2026/111xxx/CVE-2026-111497.json'].label, 'CVE List V5 · CVE-2026-111497');
  assert.equal(byUrl['https://nvd.nist.gov/vuln/detail/CVE-2026-111497'].date, '2026-10-22');
  for (const u of ['https://broccoli2shell.com/', 'https://www.imperva.com/blog/node2shell-from-brotli-data-to-remote-code-execution/']) assert.ok(byUrl[u]?.date, u);
});

test('no hand override touches Debian 13 brotli; OSV value is used', () => {
  for (const cve of watchlist.advisories) assert.equal(cve.fixStatusOverrides.filter((o) => o.ecosystem === 'Debian').length, 0);
  const deb13 = node.affected.find((a) => a.ecosystem === 'Debian' && a.release === '13' && a.package === 'brotli');
  assert.equal(deb13.source, 'osv');
  assert.equal(deb13.override, undefined);
});
