// GitHub Advisory Database (global advisories, REST). Unauthenticated or with GITHUB_TOKEN.
import { isoSeconds, isoDate, referenceType, referenceLabel, severityFromScore, creditRole } from '../normalize.js';

const API = 'https://api.github.com/advisories';
const ECO = { pip: 'PyPI', npm: 'npm', composer: 'Packagist', rubygems: 'RubyGems', nuget: 'NuGet' };

function headers(env) {
  const h = { accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28' };
  if (env.GITHUB_TOKEN) h.authorization = `Bearer ${env.GITHUB_TOKEN}`;
  return h;
}

/** Looks up by cve_id and fetches the GHSA IDs pinned in the watchlist or found via OSV/NVD (some GHSA have cve_id null). */
export async function fetchGhsa(cve, ctx, knownIds = []) {
  const h = headers(ctx.env);
  const byCve = await ctx.fetchJson(`${API}?cve_id=${encodeURIComponent(cve.id)}&per_page=100`, { headers: h });
  const advisories = [...(Array.isArray(byCve.json) ? byCve.json : [])];
  const seen = new Set(advisories.map((a) => a.ghsa_id));
  for (const id of [...new Set([...(cve.ghsaIds ?? []), ...knownIds])]) {
    if (seen.has(id)) continue;
    const r = await ctx.fetchJson(`${API}/${id}`, { headers: h, allow404: true });
    if (r.status === 200 && r.json?.ghsa_id) {
      advisories.push(r.json);
      seen.add(id);
    }
  }
  return normalizeGhsa(cve, advisories, ctx.ecosystems);
}

export function normalizeGhsa(cve, advisories, ecosystems) {
  const affected = [];
  const references = [];
  const credits = [];
  const timeline = [];
  let cvss = null;
  for (const a of advisories) {
    for (const v of a.vulnerabilities ?? []) {
      const ecosystem = ECO[v.package?.ecosystem];
      if (!ecosystem || !ecosystems.includes(ecosystem)) continue;
      const fixed = v.first_patched_version ? [v.first_patched_version] : [];
      affected.push({
        ecosystem, release: null, package: v.package.name,
        affectedRange: v.vulnerable_version_range ?? 'keine Angabe',
        fixedVersions: fixed, fixStatus: fixed.length ? 'fixed' : 'unknown',
        source: 'ghsa', sourceId: a.ghsa_id,
      });
    }
    for (const url of a.references ?? []) references.push({ url, type: referenceType(url), label: referenceLabel(url), date: null, source: 'ghsa' });
    references.push({ url: a.html_url, type: 'advisory', label: `GitHub Advisory ${a.ghsa_id}`, date: isoDate(a.published_at), source: 'ghsa' });
    for (const c of a.credits ?? []) {
      const role = creditRole(c.type, 'ghsa');
      if (role && c.user?.login) credits.push({ name: c.user.login, role, sourceUrl: a.html_url, source: 'ghsa' });
    }
    if (a.published_at) timeline.push({ date: isoSeconds(a.published_at), event: `GitHub-Advisory ${a.ghsa_id} veröffentlicht.`, sourceUrl: a.html_url, source: 'ghsa' });
    const c4 = a.cvss_severities?.cvss_v4;
    const c3 = a.cvss_severities?.cvss_v3;
    const pick = c4?.score ? { version: '4.0', ...c4 } : c3?.score ? { version: '3.1', ...c3 } : null;
    if (!cvss && pick) cvss = { version: pick.version, score: pick.score, severity: severityFromScore(pick.score), vector: pick.vector_string ?? null, source: `GitHub Advisory ${a.ghsa_id}` };
  }
  return { ids: advisories.map((a) => a.ghsa_id), affected, references, credits, timeline, cvss };
}
