import { test } from 'node:test';
import assert from 'node:assert/strict';
import { refresh } from '../src/refresh.js';
import { classify, autoMergeAllowed } from '../src/classify.js';
import { fetchNvd } from '../src/sources/nvd.js';
import { watchlist, replayFetch, noSleep, clone } from './helpers.js';

const { data: base } = await refresh({ watchlist, previous: null, fetchJson: replayFetch(), env: {}, sleep: noSleep, now: '2026-10-24T10:00:00Z' });
const later = () => ({ ...clone(base), stand: '2026-10-24T16:00:00Z' });

test('auto-merge only for pure data-only changes', () => {
  const n = later();
  n.advisories[0].epss = { score: 0.01, percentile: 0.5, date: '2026-10-24' };
  assert.equal(autoMergeAllowed(classify(base, n)), true);
});

test('never auto-merge editorial, first-run, empty or malformed results', () => {
  const kev = later();
  kev.advisories[0].kev = { exploited: true, status: 'listed', dateAdded: '2026-10-25', catalogVersion: 'x' };
  assert.equal(autoMergeAllowed(classify(base, kev)), false);
  assert.equal(autoMergeAllowed(classify(null, base)), false);
  assert.equal(autoMergeAllowed(classify(base, clone(base))), false);
  assert.equal(autoMergeAllowed(null), false);
  assert.equal(autoMergeAllowed({ level: 'data-only', items: [{ level: 'editorial' }] }), false);
});

test('NVD key goes only into the request header, never into the URL', async () => {
  const seen = [];
  const fake = async (url, opts) => { seen.push({ url, opts }); return replayFetch()(url, opts); };
  await fetchNvd({ id: 'CVE-2026-111497' }, { fetchJson: fake, env: { NVD_API_KEY: 'dummy-key-for-test' } });
  assert.equal(seen[0].opts.headers.apiKey, 'dummy-key-for-test');
  assert.doesNotMatch(seen[0].url, /dummy-key/);
  await fetchNvd({ id: 'CVE-2026-111497' }, { fetchJson: fake, env: {} });
  assert.equal(seen[1].opts.headers.apiKey, undefined);
});
