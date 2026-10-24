import { test } from 'node:test';
import assert from 'node:assert/strict';
import { refresh } from '../src/refresh.js';
import { deriveDisplayRange, applyDisplayRanges } from '../src/build.js';
import { classify } from '../src/classify.js';
import { validateData, validateWatchlist } from '../src/validate.js';
import { watchlist, replayFetch, noSleep, clone, SOURCE_URLS } from './helpers.js';

const T0 = '2026-10-24T10:00:00Z';
const run = (wl, previous, now, fail = []) => refresh({ watchlist: wl, previous, fetchJson: replayFetch({ fail }), env: {}, sleep: noSleep, now });
const { data } = await run(watchlist, null, T0);
const node = data.advisories.find((a) => a.id === 'CVE-2026-111497');
const row = (adv, eco, pkg, release = null) => adv.affected.find((a) => a.ecosystem === eco && a.package === pkg && (a.release ?? null) === release);

// --- tiny version helpers (numeric dotted versions, optional trailing .x wildcard) ---
const parts = (v) => v.split('.').map((p) => (p === 'x' ? Infinity : Number(p)));
const cmp = (a, b) => {
  const x = parts(a), y = parts(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const d = (x[i] ?? 0) - (y[i] ?? 0);
    if (d) return Math.sign(d);
  }
  return 0;
};
/** true if version v is shown as affected by a German display range. */
function shownAffected(display, v) {
  let m = display.match(/^(\S+) bis (\S+)$/);
  if (m) return cmp(v, m[1]) >= 0 && cmp(v, m[2]) <= 0;
  m = display.match(/^bis (\S+)$/);
  if (m) return cmp(v, m[1]) <= 0;
  throw new Error(`unparsed display range ${display}`);
}

// Release lists checked on 2026-10-24 (GitHub tags/releases, PyPI release history). Pre-releases left out.
const CASES = [
  { eco: 'runtime', pkg: 'bun', display: '1.0.21 bis 1.4.3', note: undefined,
    versions: ['1.0.0', '1.0.20', '1.0.21', '1.1.0', '1.2.4', '1.2.23', '1.3.0', '1.3.14', '1.4.0', '1.4.1', '1.4.2', '1.4.3', '1.4.4'],
    affected: (v) => cmp(v, '1.0.21') >= 0 && cmp(v, '1.4.4') < 0 },
  { eco: 'library', pkg: 'google/brotli', display: '1.0.3 bis 1.2.0', note: '1.0.10 und 1.1.1 nicht betroffen',
    versions: ['0.6.0', '1.0.0', '1.0.1', '1.0.2', '1.0.3', '1.0.4', '1.0.5', '1.0.6', '1.0.7', '1.0.8', '1.0.9', '1.0.10', '1.1.0', '1.1.1', '1.2.0', '1.2.1'],
    affected: (v) => cmp(v, '1.0.3') >= 0 && cmp(v, '1.2.0') <= 0 && !['1.0.10', '1.1.1'].includes(v) },
  { eco: 'PyPI', pkg: 'brotli', display: '1.0.3 bis 1.2.0', note: undefined,
    versions: ['0.5.2', '0.6.0', '1.0.1', '1.0.4', '1.0.6', '1.0.7', '1.0.8', '1.0.9', '1.1.0', '1.2.0', '1.2.1'],
    affected: (v) => cmp(v, '1.0.3') >= 0 && cmp(v, '1.2.1') < 0 },
  { eco: 'PyPI', pkg: 'brotlicffi', display: '1.0.3 bis 1.2.0.x', note: undefined,
    versions: ['0.8.0', '1.0.9.0', '1.0.9.1', '1.0.9.2', '1.1.0.0', '1.2.0.0', '1.2.0.1', '1.2.0.2', '1.2.1.0'],
    affected: (v) => cmp(v, '1.0.3') >= 0 && cmp(v, '1.2.1.0') < 0 },
];

for (const c of CASES) {
  test(`${c.eco}/${c.pkg}: displayRange "${c.display}" hides no affected version`, () => {
    const a = row(node, c.eco, c.pkg);
    assert.equal(a.displayRange, c.display);
    assert.equal(a.displayNote, c.note);
    assert.equal(a.displayRangeSource, 'watchlist');
    for (const v of c.versions) {
      if (c.affected(v)) assert.ok(shownAffected(a.displayRange, v), `${v} is affected but not shown as affected`);
    }
  });
}

test('PECL keeps the exact scope as display text (no safe simplification beyond it)', () => {
  const a = row(node, 'PECL', 'brotli');
  assert.equal(a.displayRange, '0.21.0 und master');
  assert.equal(a.affectedRange, 'Release 0.21.0 und master (gebündeltes Brotli 1.2.0)');
});

test('exceptions are only ever NOT-affected versions (displayNote convention)', () => {
  const notes = [...data.advisories.flatMap((x) => x.affected), ...watchlist.advisories.flatMap((x) => x.displayRanges ?? [])];
  for (const a of notes) {
    if (/betroffen/.test(a.displayNote ?? '')) assert.match(a.displayNote, /nicht betroffen/);
    assert.doesNotMatch(a.displayRange ?? '', /außer|\(/, 'no exceptions inside displayRange');
  }
});

test('Express/body-parser entry (row comes from PR #6) applies to that row and is inert without it', () => {
  // Row shape exactly as manualAffected on feat/curate-overlay (#6), ranges verbatim from Imperva.
  const bp = { ecosystem: 'npm', release: null, package: 'body-parser', affectedRange: 'Express 5.0.0 – 5.3.0, body-parser 2.0.0 – 2.3.0', fixedVersions: [], fixStatus: 'none' };
  const [out] = applyDisplayRanges([bp], watchlist.advisories[0].displayRanges);
  assert.equal(out.displayRange, 'Express 5.0.0 bis 5.3.0, body-parser 2.0.0 bis 2.3.0');
  assert.equal(out.displayNote, 'Den Fehler enthält der Brotli-Decoder in Node.js, nicht Express. Das Node-Update schließt ihn.');
  assert.equal(out.displayRangeSource, 'watchlist');
  assert.equal(out.affectedRange, bp.affectedRange);
  assert.equal(node.affected.some((a) => a.package === 'body-parser'), Boolean(watchlist.advisories[0].manualAffected.find((a) => a.package === 'body-parser')), 'no row is invented');
});

test('exact ranges are unchanged by display ranges', async () => {
  const wl = clone(watchlist);
  for (const a of wl.advisories) delete a.displayRanges;
  const { data: plain } = await run(wl, null, T0);
  const strip = (d) => d.advisories.map((a) => a.affected.map(({ displayRange, displayNote, displayRangeSource, ...r }) => r));
  assert.deepEqual(strip(data), strip(plain));
  assert.equal(data.meta.displayRangeNote, 'Die Tabelle fasst Versionsbereiche zusammen und nennt im Zweifel eine Version zu viel. Maßgeblich sind die exakten Bereiche.');
});

test('distro rows get a safe automatic display range', () => {
  const distro = node.affected.filter((a) => ['Debian', 'Ubuntu', 'Alpine', 'RHEL'].includes(a.ecosystem));
  assert.ok(distro.length > 0);
  assert.equal(row(node, 'Debian', 'brotli', '12').displayRange, 'vor 1.0.9-2+deb12u1');
  assert.equal(row(node, 'Alpine', 'brotli', 'v3.21').displayRange, 'vor 1.1.1-r0');
  assert.equal(row(node, 'Debian', 'nodejs', '14').displayRange, 'alle Versionen');
  assert.equal(row(node, 'Debian', 'nodejs', '14').displayRangeSource, 'auto');
  for (const a of distro) {
    if (a.displayRange === null) continue; // allowed: page falls back to affectedRange
    assert.equal(a.displayRangeSource, 'auto', `${a.ecosystem}/${a.release}/${a.package}`);
    assert.match(a.displayRange, /^(vor \S+|alle Versionen)$/, `${a.ecosystem}/${a.release}/${a.package}`);
  }
});

test('rows without a safe simplification may have displayRange null (fallback)', () => {
  const [out] = applyDisplayRanges([{ ecosystem: 'npm', release: null, package: 'x', affectedRange: '>= 1.0, < 1.2, >= 2.0, < 2.1', fixedVersions: [], fixStatus: 'fixed' }], []);
  assert.equal(out.displayRange, null);
  assert.equal(out.displayRangeSource, null);
});

test('deriveDisplayRange only simplifies patterns it cannot narrow', () => {
  assert.equal(deriveDisplayRange('< 1.2.1-r0'), 'vor 1.2.1-r0');
  assert.equal(deriveDisplayRange('>= 1.0.3, < 1.2.1'), '1.0.3 bis vor 1.2.1');
  assert.equal(deriveDisplayRange('alle Versionen (kein Fix gelistet)'), 'alle Versionen');
  assert.equal(deriveDisplayRange('1.0.3 – 1.2.0 (außer 1.0.10 und 1.1.1)'), null);
  assert.equal(deriveDisplayRange('>= 1.0, < 1.2, >= 2.0, < 2.1'), null);
});

test('the refresh pipeline keeps display ranges across runs and source outages', async () => {
  const { data: second } = await run(watchlist, data, '2026-10-24T16:00:00Z');
  const { data: third } = await run(watchlist, second, '2026-10-24T22:00:00Z', [SOURCE_URLS.osv, SOURCE_URLS.ghsa]);
  const pick = (d) => d.advisories.flatMap((a) => a.affected.map((r) => [a.id, r.ecosystem, r.release, r.package, r.displayRange, r.displayNote ?? null]));
  assert.deepEqual(pick(second), pick(data));
  assert.deepEqual(pick(third), pick(data));
  assert.equal(classify(data, second).items.filter((i) => /Anzeige-Bereich/.test(i.message)).length, 0);
});

test('curated value is dropped (and flagged editorial) when the exact range changes', () => {
  const curated = watchlist.advisories[0].displayRanges;
  const lib = { ecosystem: 'library', release: null, package: 'google/brotli', affectedRange: '1.0.0 – 1.2.0', fixedVersions: [], fixStatus: 'fixed' };
  const [out] = applyDisplayRanges([lib], curated);
  assert.equal(out.displayRange, null);
  assert.equal(out.displayNote, undefined);
  assert.equal(out.displayRangeSource, 'auto_curated_outdated');
  assert.equal(out.affectedRange, '1.0.0 – 1.2.0');

  const changed = { ...clone(data), stand: '2026-10-24T16:00:00Z' };
  const r = row(changed.advisories[0], 'PyPI', 'brotli');
  Object.assign(r, applyDisplayRanges([{ ...r, affectedRange: '>= 1.0.0, < 1.2.1' }], curated)[0]);
  const res = classify(data, changed);
  assert.equal(res.level, 'editorial');
  assert.ok(res.items.some((i) => /Anzeige-Bereich PyPI · brotli:.*displayRanges in der Watchlist prüfen/.test(i.message)));
  assert.equal(r.displayRange, '1.0.0 bis vor 1.2.1', 'falls back to the safe automatic form');
});

test('schemas accept the fields and reject incomplete curated entries', () => {
  assert.deepEqual(validateData(data).errors, []);
  assert.deepEqual(validateWatchlist(watchlist).errors, []);
  const wl = clone(watchlist);
  delete wl.advisories[0].displayRanges[0].forAffectedRange;
  assert.equal(validateWatchlist(wl).ok, false);
});
