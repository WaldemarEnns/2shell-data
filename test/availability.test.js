import { test } from 'node:test';
import assert from 'node:assert/strict';
import { refresh } from '../src/refresh.js';
import { applyAvailability } from '../src/build.js';
import { parsePeclReleases } from '../src/sources/vendor.js';
import { classify } from '../src/classify.js';
import { watchlist, replayFetch, noSleep } from './helpers.js';

const NOW = '2026-10-26T10:00:00Z';
const XML = (versions) => `<?xml version="1.0"?><a><p>brotli</p>${versions.map((v) => `<r><v>${v}</v><s>stable</s></r>`).join('')}</a>`;
const run = (versions, previous = null) => refresh({
  watchlist, previous, fetchJson: replayFetch(), env: {}, sleep: noSleep, now: NOW,
  fetchText: versions ? async () => ({ status: 200, text: XML(versions) }) : null,
});
const pecl = (data) => data.advisories[0].affected.find((a) => a.ecosystem === 'PECL' && a.package === 'brotli');

test('parsePeclReleases reads <v> entries and rejects other formats', () => {
  assert.deepEqual(parsePeclReleases(XML(['0.21.0', '0.20.0'])), ['0.21.0', '0.20.0']);
  assert.throws(() => parsePeclReleases('<html>oops</html>'));
});

test('PECL without 0.21.1: upstream_only with note and checkedAt', async () => {
  const { data } = await run(['0.21.0', '0.20.0']);
  const a = pecl(data);
  assert.equal(a.fixAvailability.state, 'upstream_only');
  assert.equal(a.fixAvailability.checkedAt, NOW);
  assert.ok(a.fixAvailability.note);
});

test('PECL lists 0.21.1: available, note dropped, change is editorial', async () => {
  const before = (await run(['0.21.0'])).data;
  const { data } = await run(['0.21.1', '0.21.0'], before);
  const a = pecl(data);
  assert.equal(a.fixAvailability.state, 'available');
  assert.equal(a.fixAvailability.note, undefined);
  const r = classify(before, data);
  assert.equal(r.level, 'editorial');
  assert.ok(r.items.some((i) => /Verfügbarkeit .*upstream_only → available/.test(i.message)));
});

test('registry not reachable: keeps the previous state', () => {
  const row = { ecosystem: 'PECL', release: null, package: 'brotli', fixedVersions: ['0.21.1'], fixAvailability: { state: 'upstream_only', registry: 'PECL', url: 'https://example.org/r', note: 'x' } };
  const prev = [{ ...row, fixAvailability: { state: 'available', registry: 'PECL', url: 'https://example.org/r', checkedAt: '2026-10-25T00:00:00Z' } }];
  const [out] = applyAvailability([row], { 'pecl:brotli': { ok: false, error: 'HTTP 503' } }, prev, NOW);
  assert.equal(out.fixAvailability.state, 'available');
  assert.equal(out.fixAvailability.note, undefined);
  assert.equal(out.fixAvailability.checkedAt, '2026-10-25T00:00:00Z');
});
