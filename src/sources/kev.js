// CISA Known Exploited Vulnerabilities catalog (one JSON file for all CVEs).
export const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

export async function fetchKev(ctx) {
  const r = await ctx.fetchJson(KEV_URL, { timeoutMs: 60000 });
  return normalizeKevCatalog(r.json);
}

export function normalizeKevCatalog(json) {
  if (!json || !Array.isArray(json.vulnerabilities)) throw new Error('KEV: unexpected catalog format');
  const entries = {};
  for (const v of json.vulnerabilities) entries[v.cveID] = v.dateAdded ?? null;
  return { catalogVersion: json.catalogVersion ?? null, entries };
}

export function kevFor(cveId, catalog) {
  const listed = Object.hasOwn(catalog.entries, cveId);
  return {
    kev: { exploited: listed, status: listed ? 'listed' : 'not_listed', dateAdded: listed ? catalog.entries[cveId] : null, catalogVersion: catalog.catalogVersion },
    timeline: listed && catalog.entries[cveId]
      ? [{ date: catalog.entries[cveId], event: 'In den CISA-KEV-Katalog aufgenommen (aktiv ausgenutzt).', sourceUrl: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', source: 'cisaKev' }]
      : [],
  };
}
