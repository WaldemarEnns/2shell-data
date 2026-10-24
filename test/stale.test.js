import { test } from 'node:test';
import assert from 'node:assert/strict';
import { refresh } from '../src/refresh.js';
import { fetchAll } from '../src/fetch-all.js';
import { buildData, AllSourcesFailedError } from '../src/build.js';
import { validateData } from '../src/validate.js';
import { watchlist, replayFetch, noSleep, SOURCE_URLS } from './helpers.js';

const T0 = '2026-10-24T10:00:00Z';
const plus = (h) => new Date(Date.parse(T0) + h * 3_600_000).toISOString().replace(/\.\d{3}Z$/, 'Z');
const run = (previous, now, fail = []) => refresh({ watchlist, previous, fetchJson: replayFetch({ fail }), env: {}, sleep: noSleep, now });

test('failed source keeps previous values; status stays ok within 12 h, lastError is set', async () => {
  const { data: first } = await run(null, T0);
  const { data } = await run(first, plus(6), [SOURCE_URLS.nvd]);
  for (const [i, adv] of data.advisories.entries()) {
    const prev = first.advisories[i];
    assert.deepEqual(adv.cvss, prev.cvss, 'cvss kept');
    assert.equal(adv.published, prev.published);
    assert.deepEqual(adv.references.filter((r) => r.source === 'nvd'), prev.references.filter((r) => r.source === 'nvd'));
    assert.equal(adv.sources.nvd.status, 'ok');
    assert.equal(adv.sources.nvd.fetchedAt, T0);
    assert.match(adv.sources.nvd.lastError, /503/);
  }
  assert.equal(data.stand, plus(6));
});

test('after 12 h without a successful NVD fetch the source is "veraltet", value still kept', async () => {
  const { data: first } = await run(null, T0);
  const { data: second } = await run(first, plus(6), [SOURCE_URLS.nvd]);
  const { data } = await run(second, plus(13), [SOURCE_URLS.nvd]);
  assert.equal(data.sources.nvd.status, 'veraltet');
  assert.equal(data.sources.nvd.fetchedAt, T0);
  assert.equal(data.advisories[0].cvss.score, first.advisories[0].cvss.score);
  assert.equal(data.sources.osv.status, 'ok');
  assert.ok(validateData(data).ok);
});

test('EPSS stays ok for 48 h, endoflife for 168 h', async () => {
  const { data: first } = await run(null, T0);
  const failing = [SOURCE_URLS.firstEpss, SOURCE_URLS.endoflife];
  const { data: d47 } = await run(first, plus(47), failing);
  assert.equal(d47.sources.firstEpss.status, 'ok');
  assert.deepEqual(d47.advisories[0].epss, first.advisories[0].epss);
  const { data: d49 } = await run(d47, plus(49), failing);
  assert.equal(d49.sources.firstEpss.status, 'veraltet');
  assert.equal(d49.sources.endoflife.status, 'ok');
  assert.deepEqual(d49.eolCycles, first.eolCycles);
  const { data: d169 } = await run(d49, plus(169), failing);
  assert.equal(d169.sources.endoflife.status, 'veraltet');
  assert.equal(d169.advisories[0].runtimes.find((r) => r.cycle === '20').status, 'kein Fix (EOL)');
});

test('KEV is tri-state: unknown when the fetch fails and there is no previous value', async () => {
  const { data } = await run(null, T0, [SOURCE_URLS.cisaKev, SOURCE_URLS.firstEpss]);
  for (const adv of data.advisories) {
    assert.deepEqual(adv.kev, { exploited: null, status: 'unknown', dateAdded: null, catalogVersion: null });
    assert.equal(adv.epss, null);
    assert.equal(adv.sources.cisaKev.status, 'fehlt');
  }
  assert.equal(data.sources.cisaKev.status, 'fehlt');
  assert.equal(data.sources.cisaKev.fetchedAt, null);
  assert.ok(validateData(data).ok);
});

test('stale OSV/GHSA keep their affected entries', async () => {
  const { data: first } = await run(null, T0);
  const { data } = await run(first, plus(1), [SOURCE_URLS.osv, SOURCE_URLS.ghsa]);
  assert.deepEqual(data.advisories[0].affected, first.advisories[0].affected.map((a) => (a.fixRef?.state ? { ...a, fixRef: { ...a.fixRef, checkedAt: plus(1) } } : a)));
  assert.deepEqual(data.advisories[0].aliases.ids, first.advisories[0].aliases.ids);
});

test('if every source fails, the run is not a successful run', async () => {
  const results = await fetchAll(watchlist, { fetchJson: replayFetch({ fail: ['http'] }), env: {}, sleep: noSleep });
  assert.throws(() => buildData({ watchlist, previous: null, results, now: T0 }), AllSourcesFailedError);
});

test('published from OSV survives an OSV outage', async () => {
  const { data: first } = await run(null, T0);
  const { data } = await run(first, plus(1), [SOURCE_URLS.osv]);
  assert.equal(data.advisories[0].published, first.advisories[0].published);
  assert.equal(data.advisories[0].publishedSource, 'osv');
});
