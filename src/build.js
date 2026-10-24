// Turns fetch results + watchlist (+ previous data for the stale fallback) into data/2shell.json.
import { STALE_AFTER_HOURS, BANNER_STALE_AFTER_HOURS, REFRESH_INTERVAL_HOURS, PER_CVE_SOURCES } from './config.js';
import { normalizeUrl } from './normalize.js';

const ECOSYSTEM_ORDER = ['runtime', 'library', 'npm', 'PyPI', 'Packagist', 'PECL', 'RubyGems', 'NuGet', 'Debian', 'Ubuntu', 'Alpine', 'RHEL', 'other'];
const SOURCE_PRECEDENCE = { watchlist: 0, ghsa: 1, osv: 2 };
const STATUS_RANK = { ok: 0, veraltet: 1, fehlt: 2 };

export class AllSourcesFailedError extends Error {}

function hoursBetween(a, b) {
  return (new Date(b).getTime() - new Date(a).getTime()) / 3_600_000;
}

/** Status of one source from its last successful fetch. */
export function sourceStatus(name, { ok, error, prevFetchedAt, now }) {
  const staleAfterHours = STALE_AFTER_HOURS[name];
  const fetchedAt = ok ? now : prevFetchedAt ?? null;
  let status;
  if (!fetchedAt) status = 'fehlt';
  else status = hoursBetween(fetchedAt, now) > staleAfterHours ? 'veraltet' : 'ok';
  return { status, fetchedAt, lastAttemptAt: now, lastError: ok ? null : error ?? 'unknown error', staleAfterHours };
}

function aggregateStatus(name, entries, now) {
  if (!entries.length) return null;
  const worst = entries.reduce((w, e) => (STATUS_RANK[e.status] > STATUS_RANK[w.status] ? e : w), entries[0]);
  const fetched = entries.map((e) => e.fetchedAt);
  const oldest = fetched.includes(null) ? null : fetched.sort()[0];
  return { status: worst.status, fetchedAt: oldest, lastAttemptAt: now, lastError: entries.find((e) => e.lastError)?.lastError ?? null, staleAfterHours: STALE_AFTER_HOURS[name] };
}

/** Previous values owned by one source, used when that source fails this run. */
export function previousFragment(name, prev) {
  const own = (list) => (list ?? []).filter((x) => x.source === name);
  switch (name) {
    case 'osv':
      return { ids: (prev?.aliases?.ids ?? []).filter((id) => !id.startsWith('GHSA-')), title: prev?.title ?? null, published: null, modified: null, affected: own(prev?.affected), references: own(prev?.references), credits: own(prev?.credits) };
    case 'nvd':
      return prev ? { cvss: prev.cvss ? withoutVendorRatings(prev.cvss) : null, published: prev.published ?? null, modified: prev.modified ?? null, references: own(prev.references), timeline: own(prev.timeline) } : { cvss: null, published: null, modified: null, references: [], timeline: [] };
    case 'ghsa':
      return { ids: (prev?.aliases?.ids ?? []).filter((id) => id.startsWith('GHSA-')), affected: own(prev?.affected), references: own(prev?.references), credits: own(prev?.credits), timeline: own(prev?.timeline), cvss: null };
    case 'cisaKev':
      return { kev: prev?.kev ?? { exploited: null, status: 'unknown', dateAdded: null, catalogVersion: null }, timeline: own(prev?.timeline) };
    case 'firstEpss':
      return { epss: prev?.epss ?? null };
    default:
      return {};
  }
}

function withoutVendorRatings({ vendorRatings, ...rest }) {
  return rest;
}

const affectedKey = (a) => `${a.ecosystem}|${a.release ?? ''}|${String(a.package).toLowerCase()}`;
const refKey = (url) => normalizeUrl(String(url).split('#')[0]);

function mergeAffected(lists) {
  const byKey = new Map();
  for (const item of lists.flat()) {
    const key = affectedKey(item);
    const cur = byKey.get(key);
    if (!cur || SOURCE_PRECEDENCE[item.source] < SOURCE_PRECEDENCE[cur.source]) byKey.set(key, item);
    else if (cur.source === item.source && cur.sourceId !== item.sourceId) {
      // Same package in two records of one source: union the fixed versions.
      cur.fixedVersions = [...new Set([...cur.fixedVersions, ...item.fixedVersions])];
      if (cur.fixedVersions.length) cur.fixStatus = 'fixed';
    }
  }
  return [...byKey.values()].sort((a, b) =>
    ECOSYSTEM_ORDER.indexOf(a.ecosystem) - ECOSYSTEM_ORDER.indexOf(b.ecosystem) ||
    String(a.release ?? '').localeCompare(String(b.release ?? ''), 'en', { numeric: true }) ||
    a.package.localeCompare(b.package));
}

function dedupe(list, keyFn) {
  const seen = new Set();
  return list.filter((x) => {
    const k = keyFn(x);
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

/** Applies watchlist fixStatus overrides. pending/none can only come from here. */
export function applyOverrides(affected, overrides = []) {
  return affected.map((a) => {
    const o = overrides.find((x) => x.ecosystem === a.ecosystem && x.package.toLowerCase() === a.package.toLowerCase() && (x.release == null || x.release === a.release));
    if (!o) return a;
    return { ...a, fixStatus: o.fixStatus, fixRef: { url: o.fixRef.url, ...(o.fixRef.label ? { label: o.fixRef.label } : {}) }, ...(o.note ? { note: o.note } : {}), override: true };
  });
}

function manualAffected(cve) {
  return (cve.manualAffected ?? []).map(({ sourceUrl, verifiedBy, verifiedAt, ...rest }) => ({ release: null, ...rest, source: 'watchlist', sourceId: sourceUrl }));
}

function attachFixRefState(affected, vendor, prevAffected, now) {
  return affected.map((a) => {
    if (!a.fixRef?.url) return a;
    const v = vendor[a.fixRef.url];
    const prev = (prevAffected ?? []).find((p) => affectedKey(p) === affectedKey(a))?.fixRef;
    if (v?.ok) return { ...a, fixRef: { ...a.fixRef, state: v.data, checkedAt: now } };
    if (prev?.state) return { ...a, fixRef: { ...a.fixRef, state: prev.state, checkedAt: prev.checkedAt } };
    return a;
  });
}

function runtimesFor(cve, eolCycles) {
  return (cve.runtimes ?? []).map((r) => {
    const cyc = r.eolProduct ? (eolCycles[r.eolProduct] ?? []).find((c) => c.cycle === r.cycle) : null;
    const status = r.fixedIn ? 'gepatcht' : cyc?.isEol ? 'kein Fix (EOL)' : 'offen';
    return { product: r.product, cycle: r.cycle, fixedIn: r.fixedIn, eol: cyc ? cyc.eol : null, latest: cyc?.latest ?? null, status, sourceUrl: r.sourceUrl };
  });
}

/**
 * @param {{watchlist:any, previous:any|null, results:any, now:string}} args
 */
export function buildData({ watchlist, previous, results, now }) {
  const prevById = new Map((previous?.advisories ?? []).map((a) => [a.id, a]));
  const prevSources = previous?.sources ?? {};

  // Was anything fetched at all? If not, this run is not a successful run.
  const anyOk = Object.values(results.perCve).some((s) => Object.values(s).some((r) => r.ok)) ||
    Object.values(results.endoflife).some((r) => r.ok);
  if (!anyOk) throw new AllSourcesFailedError('All sources failed; keeping previous data.');

  // endoflife (per product)
  const eolCycles = {};
  const eolStatuses = [];
  for (const [product, r] of Object.entries(results.endoflife)) {
    eolCycles[product] = r.ok ? r.data : previous?.eolCycles?.[product] ?? [];
    eolStatuses.push(sourceStatus('endoflife', { ok: r.ok, error: r.error, prevFetchedAt: prevSources.endoflife?.fetchedAt, now }));
  }
  const vendorStatuses = Object.values(results.vendor).map((r) => sourceStatus('vendor', { ok: r.ok, error: r.error, prevFetchedAt: prevSources.vendor?.fetchedAt, now }));

  const perSourceStatuses = Object.fromEntries(PER_CVE_SOURCES.map((s) => [s, []]));
  const advisories = watchlist.advisories.map((cve) => {
    const prev = prevById.get(cve.id) ?? null;
    const frag = {};
    const sources = {};
    for (const name of PER_CVE_SOURCES) {
      const r = results.perCve[cve.id]?.[name] ?? { ok: false, error: 'not fetched' };
      frag[name] = r.ok ? r.data : previousFragment(name, prev);
      sources[name] = sourceStatus(name, { ok: r.ok, error: r.error, prevFetchedAt: prev?.sources?.[name]?.fetchedAt, now });
      perSourceStatuses[name].push(sources[name]);
    }
    const { osv, nvd, ghsa, cisaKev, firstEpss } = frag;

    let affected = mergeAffected([manualAffected(cve), ghsa.affected, osv.affected]);
    affected = applyOverrides(affected, cve.fixStatusOverrides);
    affected = attachFixRefState(affected, results.vendor, prev?.affected, now);

    const cvssBase = nvd.cvss ?? ghsa.cvss ?? null;
    const cvss = cvssBase ? { ...cvssBase, vendorRatings: cve.vendorRatings ?? [] } : null;

    const editorialRefs = (cve.references ?? []).map((r) => ({ date: null, ...r, source: 'watchlist' }));
    const references = dedupe([...editorialRefs, ...nvd.references, ...ghsa.references, ...osv.references], (r) => refKey(r.url));

    const timeline = dedupe([
      ...(cve.timeline ?? []).map((t) => ({ ...t, source: 'watchlist' })),
      ...nvd.timeline, ...ghsa.timeline, ...cisaKev.timeline,
    ], (t) => `${t.date}|${t.event}`).sort((a, b) => a.date.localeCompare(b.date));

    const credits = dedupe([
      ...(cve.credits ?? []).map((c) => ({ ...c, source: 'watchlist' })),
      ...osv.credits, ...ghsa.credits,
    ], (c) => `${c.name.toLowerCase()}|${c.role}`);

    const ids = [...new Set([...ghsa.ids, ...osv.ids])].filter((id) => id !== cve.id)
      .sort((a, b) => (b.startsWith('GHSA-') - a.startsWith('GHSA-')) || a.localeCompare(b));

    const out = {
      id: cve.id,
      slug: cve.slug,
      landingUrl: cve.landingUrl ?? null,
      aliases: { ids, nicknames: cve.nicknames ?? [] },
      title: cve.title ?? osv.title ?? prev?.title ?? cve.id,
      published: nvd.published ?? osv.published ?? prev?.published ?? null,
      modified: nvd.modified ?? osv.modified ?? prev?.modified ?? null,
      cvss,
      kev: cisaKev.kev,
      epss: firstEpss.epss,
      exploitation: cve.exploitation ?? [],
      affected,
      runtimes: runtimesFor(cve, eolCycles),
      timeline,
      credits,
      references,
      editorial: cve.editorial ?? { markdownPath: null, approvedBy: null, approvedAt: null },
      sources,
    };
    return out;
  });

  const globalSources = {};
  for (const name of PER_CVE_SOURCES) globalSources[name] = aggregateStatus(name, perSourceStatuses[name], now);
  const eolAgg = aggregateStatus('endoflife', eolStatuses, now);
  if (eolAgg) globalSources.endoflife = eolAgg;
  const vendorAgg = aggregateStatus('vendor', vendorStatuses, now);
  if (vendorAgg) globalSources.vendor = vendorAgg;

  return {
    $schema: '../schema/2shell.schema.json',
    schemaVersion: '1',
    stand: now,
    refreshIntervalHours: REFRESH_INTERVAL_HOURS,
    meta: { bannerStaleAfterHours: BANNER_STALE_AFTER_HOURS, staleAfterHours: { ...STALE_AFTER_HOURS }, generator: '2shell-data' },
    sources: globalSources,
    eolCycles,
    advisories,
  };
}
