// endoflife.date API v1: release cycles with EOL dates.
export const EOL_API = 'https://endoflife.date/api/v1/products/';

export async function fetchEndoflife(product, ctx) {
  const r = await ctx.fetchJson(`${EOL_API}${encodeURIComponent(product)}/`);
  return normalizeEndoflife(r.json);
}

export function normalizeEndoflife(json) {
  const releases = json?.result?.releases;
  if (!Array.isArray(releases)) throw new Error('endoflife: unexpected response format');
  return releases.map((r) => ({ cycle: String(r.name), eol: r.eolFrom ?? (r.isEol ? true : null), isEol: Boolean(r.isEol), latest: r.latest?.name ?? null }));
}
