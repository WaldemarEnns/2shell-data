// NVD API 2.0: CVSS, dates, references. Optional NVD_API_KEY (header "apiKey").
import { isoSeconds, referenceType, referenceLabel, cvssSourceName } from '../normalize.js';

const API = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=';
// Public limit: 5 requests / 30 s without key, 50 / 30 s with key.
export const nvdDelayMs = (env) => (env.NVD_API_KEY ? 700 : 6500);

export async function fetchNvd(cve, ctx) {
  const headers = ctx.env.NVD_API_KEY ? { apiKey: ctx.env.NVD_API_KEY } : {};
  const r = await ctx.fetchJson(API + encodeURIComponent(cve.id), { headers });
  return normalizeNvd(cve, r.json);
}

export function normalizeNvd(cve, json) {
  const item = json?.vulnerabilities?.find((v) => v.cve?.id === cve.id)?.cve ?? null;
  if (!item) return { hasRecord: false, published: null, modified: null, cvss: null, references: [], timeline: [], vulnStatus: null };
  const metrics = [];
  for (const [key, version] of [['cvssMetricV40', '4.0'], ['cvssMetricV31', '3.1']]) {
    for (const m of item.metrics?.[key] ?? []) {
      metrics.push({
        version,
        score: m.cvssData.baseScore,
        severity: m.cvssData.baseSeverity,
        // NVD expands v4 vectors with all "X" (not defined) metrics; strip them for display.
        vector: stripUndefined(m.cvssData.vectorString),
        source: m.source === 'nvd@nist.gov' ? 'NVD' : `${cvssSourceName(m.source)} via NVD`,
        primary: m.type === 'Primary',
      });
    }
  }
  // Prefer CVSS 4.0, then Primary over Secondary. All others are kept in "additional".
  metrics.sort((a, b) => (b.version === '4.0') - (a.version === '4.0') || b.primary - a.primary);
  const strip = ({ primary, ...rest }) => rest;
  const cvss = metrics.length ? { ...strip(metrics[0]), additional: metrics.slice(1).map(strip) } : null;
  const references = (item.references ?? []).map((ref) => ({ url: ref.url, type: referenceType(ref.url), label: referenceLabel(ref.url), date: null, source: 'nvd' }));
  const published = isoSeconds(item.published);
  return {
    hasRecord: true,
    vulnStatus: item.vulnStatus ?? null,
    published,
    modified: isoSeconds(item.lastModified),
    cvss,
    references,
    timeline: published ? [{ date: published, event: 'CVE-Eintrag bei NVD veröffentlicht.', sourceUrl: `https://nvd.nist.gov/vuln/detail/${cve.id}`, source: 'nvd' }] : [],
    description: item.descriptions?.find((d) => d.lang === 'en')?.value ?? null,
  };
}

export function stripUndefined(vector) {
  if (!vector) return null;
  return vector.split('/').filter((part) => !/:X$/.test(part)).join('/');
}

