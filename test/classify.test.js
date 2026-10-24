import { test } from 'node:test';
import assert from 'node:assert/strict';
import { refresh } from '../src/refresh.js';
import { classify, summaryMarkdown } from '../src/classify.js';
import { watchlist, replayFetch, noSleep, clone } from './helpers.js';

const { data: base } = await refresh({ watchlist, previous: null, fetchJson: replayFetch(), env: {}, sleep: noSleep, now: '2026-10-24T10:00:00Z' });
const later = () => ({ ...clone(base), stand: '2026-10-24T16:00:00Z' });
const levelOf = (n) => classify(base, n).level;

test('first run: every CVE is new -> editorial', () => {
  const r = classify(null, base);
  assert.equal(r.level, 'editorial');
  assert.equal(r.items.length, 3);
});

test('identical data -> none; only stand -> data-only', () => {
  assert.equal(classify(base, clone(base)).level, 'none');
  assert.equal(levelOf(later()), 'data-only');
});

test('EPSS, references, new fixed versions -> data-only', () => {
  const n = later();
  n.advisories[0].epss = { score: 0.01, percentile: 0.5, date: '2026-10-24' };
  n.advisories[0].references.push({ url: 'https://example.org/new', type: 'news', label: 'x', date: null, source: 'osv' });
  const deb = n.advisories[0].affected.find((a) => a.ecosystem === 'Debian' && a.fixStatus === 'unknown' && a.package === 'brotli');
  deb.fixedVersions = ['1.2.1-1']; deb.fixStatus = 'fixed';
  const r = classify(base, n);
  assert.equal(r.level, 'data-only');
  assert.ok(r.items.some((i) => /EPSS/.test(i.message)));
  assert.ok(r.items.some((i) => /Neue Fix-Version/.test(i.message)));
});

test('KEV becomes true -> editorial', () => {
  const n = later();
  n.advisories[1].kev = { exploited: true, status: 'listed', dateAdded: '2026-10-25', catalogVersion: '2026.10.25' };
  assert.equal(levelOf(n), 'editorial');
});

test('CVSS severity change -> editorial; score change within severity -> data-only', () => {
  const a = later(); a.advisories[0].cvss.severity = 'HIGH'; a.advisories[0].cvss.score = 8.7;
  assert.equal(levelOf(a), 'editorial');
  const b = later(); b.advisories[0].cvss.score = 9.3;
  assert.equal(levelOf(b), 'data-only');
});

test('new ecosystem or runtime line -> editorial', () => {
  const a = later();
  a.advisories[1].affected.push({ ecosystem: 'Alpine', release: 'v3.24', package: 'php84', affectedRange: '< 8.4.27-r0', fixedVersions: ['8.4.27-r0'], fixStatus: 'fixed', source: 'osv' });
  assert.equal(levelOf(a), 'editorial');
  const b = later();
  b.advisories[0].runtimes.push({ product: 'Node.js', cycle: '18', fixedIn: null, eol: '2025-04-30', latest: null, status: 'kein Fix (EOL)' });
  assert.equal(levelOf(b), 'editorial');
});

test('new CVE in the watchlist -> editorial', () => {
  const n = later();
  n.advisories.push({ ...clone(base.advisories[1]), id: 'CVE-2026-999999' });
  assert.equal(levelOf(n), 'editorial');
});

test('fixStatus change involving pending/none, or fixRef state change -> editorial', () => {
  const a = later();
  const pecl = a.advisories[0].affected.find((x) => x.ecosystem === 'PECL');
  pecl.fixStatus = 'fixed';
  assert.equal(levelOf(a), 'editorial');
  const b = later();
  b.advisories[0].affected.find((x) => x.ecosystem === 'PECL').fixRef.state = 'merged';
  const r = classify(base, b);
  assert.equal(r.level, 'editorial');
  assert.ok(r.items.some((i) => /open → merged/.test(i.message)));
});

test('summary markdown has the key values and a "Text prüfen" checklist for editorial changes', () => {
  const n = later();
  n.advisories[1].kev = { exploited: true, status: 'listed', dateAdded: '2026-10-25', catalogVersion: '2026.10.25' };
  const md = summaryMarkdown(classify(base, n), n);
  assert.match(md, /### Text prüfen/);
  assert.match(md, /- \[ \] \*\*CVE-2026-109618\*\*: KEV: jetzt gelistet/);
  assert.match(md, /\| CVE-2026-111497 \| 9\.2 CRITICAL \(v4\.0\) \| nicht gelistet \|/);
  assert.doesNotMatch(summaryMarkdown(classify(base, later()), later()), /Text prüfen/);
});
