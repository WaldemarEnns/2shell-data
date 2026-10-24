import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { refresh } from '../src/refresh.js';
import { validateData, validateWatchlist } from '../src/validate.js';
import { watchlist, replayFetch, noSleep, clone } from './helpers.js';

const NOW = '2026-10-24T10:00:00Z';

test('build from recorded fixtures validates against schema/2shell.schema.json', async () => {
  const { data } = await refresh({ watchlist, previous: null, fetchJson: replayFetch(), env: {}, sleep: noSleep, now: NOW });
  const v = validateData(data);
  assert.deepEqual(v.errors, []);
  assert.equal(data.stand, NOW);
  assert.equal(data.meta.bannerStaleAfterHours, 24);
  assert.deepEqual(data.meta.staleAfterHours, { osv: 12, nvd: 12, ghsa: 12, cisaKev: 12, vendor: 12, firstEpss: 48, endoflife: 168 });
  assert.deepEqual(data.advisories.map((a) => a.id), ['CVE-2026-111497', 'CVE-2026-109618', 'CVE-2026-109619']);
  for (const s of Object.values(data.sources)) assert.equal(s.status, 'ok');
});

test('recorded values come through unchanged', async () => {
  const { data } = await refresh({ watchlist, previous: null, fetchJson: replayFetch(), env: {}, sleep: noSleep, now: NOW });
  const node = data.advisories[0];
  assert.equal(node.cvss.version, '4.0');
  assert.equal(node.cvss.score, 9.2);
  assert.equal(node.cvss.severity, 'CRITICAL');
  assert.equal(node.cvss.vector, 'CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N');
  assert.equal(node.kev.status, 'not_listed');
  assert.equal(node.kev.exploited, false);
  assert.ok(node.aliases.ids.includes('GHSA-9v8h-qqgm-4m35'));
  assert.ok(node.affected.some((a) => a.ecosystem === 'PyPI' && a.package === 'brotli' && a.fixedVersions.includes('1.2.1')));
  assert.ok(node.affected.some((a) => a.ecosystem === 'PyPI' && a.package === 'brotlicffi' && a.fixedVersions.includes('1.2.1.0')));
  const rt = Object.fromEntries(node.runtimes.map((r) => [`${r.product} ${r.cycle}`, r]));
  assert.equal(rt['Node.js 24'].fixedIn, '24.22.1');
  assert.equal(rt['Node.js 24'].status, 'gepatcht');
  assert.equal(rt['Node.js 20'].status, 'kein Fix (EOL)');
  const php = data.advisories[1];
  assert.ok(php.cvss.additional.some((m) => m.version === '3.1'));
  assert.equal(php.landingUrl, 'https://php-check.waldemarenns.de/');
});

test("Desi's example structure (BEISPIEL values replaced) validates", () => {
  const ex = JSON.parse(readFileSync(new URL('./fixtures/desi-example-shape.json', import.meta.url), 'utf8'));
  assert.deepEqual(validateData(ex).errors, []);
});

test('schema rejects broken data', async () => {
  const { data } = await refresh({ watchlist, previous: null, fetchJson: replayFetch(), env: {}, sleep: noSleep, now: NOW });
  const bad1 = clone(data); delete bad1.stand;
  const bad2 = clone(data); bad2.advisories[0].affected[0].fixStatus = 'maybe';
  const bad3 = clone(data); bad3.advisories[0].kev.status = 'perhaps';
  const bad4 = clone(data); bad4.sources.osv.status = 'stale';
  for (const bad of [bad1, bad2, bad3, bad4]) assert.equal(validateData(bad).ok, false);
});

test('watchlist: pending/none in manualAffected needs verifiedBy, verifiedAt and fixRef', () => {
  assert.deepEqual(validateWatchlist(watchlist).errors, []);
  const wl = clone(watchlist);
  const pecl = wl.advisories[0].manualAffected.find((a) => a.ecosystem === 'PECL');
  delete pecl.verifiedBy;
  assert.equal(validateWatchlist(wl).ok, false);
});
