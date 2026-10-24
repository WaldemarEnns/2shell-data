// FIRST EPSS API, one batch request for all watchlist CVEs.
export const EPSS_API = 'https://api.first.org/data/v1/epss?cve=';

export async function fetchEpss(ids, ctx) {
  const r = await ctx.fetchJson(EPSS_API + ids.join(','));
  return normalizeEpss(r.json);
}

export function normalizeEpss(json) {
  if (!json || !Array.isArray(json.data)) throw new Error('EPSS: unexpected response format');
  const out = {};
  for (const d of json.data) out[d.cve] = { score: Number(d.epss), percentile: Number(d.percentile), date: d.date };
  return out;
}
