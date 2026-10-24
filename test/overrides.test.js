import { test } from 'node:test';
import assert from 'node:assert/strict';
import { refresh } from '../src/refresh.js';
import { applyOverrides } from '../src/build.js';
import { describeRanges } from '../src/normalize.js';
import { watchlist, replayFetch, noSleep, clone } from './helpers.js';

const NOW = '2026-10-24T10:00:00Z';
const build = (wl) => refresh({ watchlist: wl, previous: null, fetchJson: replayFetch(), env: {}, sleep: noSleep, now: NOW }).then((r) => r.data);

test('automatic entries are only ever fixed or unknown', async () => {
  const data = await build(watchlist);
  for (const adv of data.advisories) {
    for (const a of adv.affected.filter((x) => x.source !== 'watchlist')) assert.ok(['fixed', 'unknown'].includes(a.fixStatus), `${a.ecosystem} ${a.package}: ${a.fixStatus}`);
  }
});

test('PHP brotli extension is pending with PR #105 from the watchlist', async () => {
  const data = await build(watchlist);
  const pecl = data.advisories[0].affected.find((a) => a.ecosystem === 'PECL' && a.package === 'brotli');
  assert.equal(pecl.fixStatus, 'pending');
  assert.equal(pecl.fixRef.url, 'https://github.com/kjdev/php-ext-brotli/pull/105');
  assert.equal(pecl.fixRef.state, 'open');
  assert.equal(pecl.fixRef.checkedAt, NOW);
  assert.equal(pecl.source, 'watchlist');
});

test('a fixStatus override on a fetched entry wins and carries its fixRef', async () => {
  const wl = clone(watchlist);
  wl.advisories[0].fixStatusOverrides.push({
    ecosystem: 'Debian', release: '14', package: 'brotli', fixStatus: 'pending',
    fixRef: { url: 'https://example.org/debian-bug', label: 'Test' }, verifiedBy: 'test', verifiedAt: NOW,
  });
  const data = await build(wl);
  const deb14 = data.advisories[0].affected.find((a) => a.ecosystem === 'Debian' && a.release === '14' && a.package === 'brotli');
  assert.equal(deb14.fixStatus, 'pending');
  assert.equal(deb14.fixRef.url, 'https://example.org/debian-bug');
  const deb12 = data.advisories[0].affected.find((a) => a.ecosystem === 'Debian' && a.release === '12' && a.package === 'brotli');
  assert.equal(deb12.fixStatus, 'fixed', 'other releases untouched');
});

test('applyOverrides without release matches every release', () => {
  const out = applyOverrides(
    [{ ecosystem: 'Ubuntu', release: '22.04:LTS', package: 'nodejs', fixStatus: 'unknown' }, { ecosystem: 'Ubuntu', release: '24.04:LTS', package: 'nodejs', fixStatus: 'unknown' }],
    [{ ecosystem: 'Ubuntu', package: 'nodejs', fixStatus: 'none', fixRef: { url: 'https://example.org/x' }, verifiedBy: 't', verifiedAt: NOW }],
  );
  assert.deepEqual(out.map((a) => a.fixStatus), ['none', 'none']);
});

test('describeRanges formats OSV events', () => {
  assert.deepEqual(describeRanges([{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '1.2.1' }] }]), { affectedRange: '< 1.2.1', fixedVersions: ['1.2.1'] });
  assert.deepEqual(describeRanges([{ type: 'ECOSYSTEM', events: [{ introduced: '0' }] }]).fixedVersions, []);
  assert.equal(describeRanges([{ type: 'SEMVER', events: [{ introduced: '1.0.3' }, { fixed: '1.0.10' }, { introduced: '1.1.0' }, { fixed: '1.1.1' }] }]).affectedRange, '>= 1.0.3, < 1.0.10 | >= 1.1.0, < 1.1.1');
});
