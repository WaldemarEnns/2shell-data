// Runs every fetcher and records success or failure per source. Never throws for a single failing source.
import { fetchJson as defaultFetchJson, fetchText as defaultFetchText } from './http.js';
import { fetchOsv } from './sources/osv.js';
import { fetchNvd, nvdDelayMs } from './sources/nvd.js';
import { fetchGhsa } from './sources/ghsa.js';
import { fetchKev, kevFor } from './sources/kev.js';
import { fetchEpss } from './sources/epss.js';
import { fetchEndoflife } from './sources/endoflife.js';
import { fetchPullState, fetchPeclReleases } from './sources/vendor.js';

const defaultSleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function attempt(fn) {
  try {
    return { ok: true, data: await fn() };
  } catch (err) {
    return { ok: false, error: String(err?.message ?? err).slice(0, 300) };
  }
}

/**
 * @returns {Promise<{perCve: Record<string, Record<string, {ok:boolean,data?:any,error?:string}>>, endoflife: Record<string, any>, vendor: Record<string, any>}>}
 */
export async function fetchAll(watchlist, { fetchJson = defaultFetchJson, fetchText, env = process.env, sleep = defaultSleep } = {}) {
  // Real text fetches only in real runs; with an injected fetchJson (tests) the registry check is skipped unless fetchText is injected too.
  if (fetchText === undefined) fetchText = fetchJson === defaultFetchJson ? defaultFetchText : null;
  const ctx = { fetchJson, fetchText, env, ecosystems: watchlist.ecosystems };
  const ids = watchlist.advisories.map((a) => a.id);
  const perCve = Object.fromEntries(ids.map((id) => [id, {}]));

  const kev = await attempt(() => fetchKev(ctx));
  const epss = await attempt(() => fetchEpss(ids, ctx));

  let first = true;
  for (const cve of watchlist.advisories) {
    const slot = perCve[cve.id];
    slot.osv = await attempt(() => fetchOsv(cve, ctx));
    if (!first) await sleep(nvdDelayMs(env));
    first = false;
    slot.nvd = await attempt(() => fetchNvd(cve, ctx));
    const known = new Set();
    for (const id of slot.osv.data?.ids ?? []) if (id.startsWith('GHSA-')) known.add(id);
    for (const ref of slot.nvd.data?.references ?? []) {
      const m = ref.url.match(/github\.com\/advisories\/(GHSA(?:-[a-z0-9]{4}){3})/i);
      if (m) known.add(m[1]);
    }
    slot.ghsa = await attempt(() => fetchGhsa(cve, ctx, [...known]));
    slot.cisaKev = kev.ok ? { ok: true, data: kevFor(cve.id, kev.data) } : kev;
    slot.firstEpss = epss.ok ? { ok: true, data: { epss: epss.data[cve.id] ?? null } } : epss;
  }

  const endoflife = {};
  for (const product of watchlist.eolProducts ?? []) endoflife[product] = await attempt(() => fetchEndoflife(product, ctx));

  const vendor = {};
  for (const cve of watchlist.advisories) {
    for (const item of [...(cve.manualAffected ?? []), ...(cve.fixStatusOverrides ?? [])]) {
      const url = item.fixRef?.url;
      if (url && /github\.com\/[^/]+\/[^/]+\/pull\/\d+/.test(url) && !vendor[url]) vendor[url] = await attempt(() => fetchPullState(url, ctx));
      const fa = item.fixAvailability;
      const key = fa?.registry === 'PECL' ? `pecl:${String(fa.package ?? item.package).toLowerCase()}` : null;
      if (key && ctx.fetchText && !vendor[key]) vendor[key] = await attempt(() => fetchPeclReleases(fa.package ?? item.package, ctx));
    }
  }
  return { perCve, endoflife, vendor };
}
