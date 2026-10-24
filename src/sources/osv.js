// OSV.dev: CVE record, its aliases (PYSEC, GHSA, ...) and distro records (Debian, Ubuntu, Alpine).
import { describeRanges, splitEcosystem, isoSeconds, referenceType, referenceLabel, referenceDate, creditRole } from '../normalize.js';

const API = 'https://api.osv.dev/v1/vulns/';
const DISTRO_PREFIXES = ['DEBIAN', 'UBUNTU', 'ALPINE'];
// Bitnami (BIT-*) records only cover the Bitnami ecosystem, which is not on the watchlist.
const SKIP_ALIAS = /^BIT-/;

export async function fetchOsv(cve, ctx) {
  const { fetchJson, ecosystems } = ctx;
  const records = [];
  const ids = new Set();
  const main = await fetchJson(API + cve.id, { allow404: true });
  if (main.status === 200) records.push(main.json);
  else {
    // OSV answers 404 for some CVEs but names the aliases it does know.
    const m = String(main.json?.message ?? '').match(/aliases were:\s*(.+)$/);
    if (m) m[1].split(/\s+/).filter(Boolean).forEach((id) => ids.add(id));
  }
  for (const id of main.json?.aliases ?? []) ids.add(id);
  for (const id of main.json?.related ?? []) if (/^(PYSEC|GHSA)-/.test(id)) ids.add(id);

  const extra = [...ids].filter((id) => !SKIP_ALIAS.test(id) && id !== cve.id);
  extra.push(...DISTRO_PREFIXES.map((p) => `${p}-${cve.id}`));
  for (const id of [...new Set(extra)]) {
    const r = await fetchJson(API + id, { allow404: true });
    if (r.status === 200) {
      records.push(r.json);
      ids.add(id);
    }
  }
  return normalizeOsv(cve, records, [...ids], ecosystems);
}

export function normalizeOsv(cve, records, ids, ecosystems) {
  const main = records.find((r) => r.id === cve.id) ?? null;
  const affected = [];
  const references = [];
  const credits = [];
  for (const rec of records) {
    for (const a of rec.affected ?? []) {
      const { ecosystem, release } = splitEcosystem(a.package?.ecosystem ?? '');
      if (!ecosystem || !ecosystems.includes(ecosystem)) continue;
      const { affectedRange, fixedVersions } = describeRanges(a.ranges);
      affected.push({
        ecosystem,
        release,
        package: a.package.name,
        affectedRange,
        fixedVersions,
        fixStatus: fixedVersions.length ? 'fixed' : 'unknown',
        urgency: a.ecosystem_specific?.urgency ?? null,
        source: 'osv',
        sourceId: rec.id,
      });
    }
    for (const c of rec.credits ?? []) {
      const role = creditRole(c.type, 'osv');
      if (role) credits.push({ name: c.name, role, sourceUrl: `https://osv.dev/vulnerability/${rec.id}`, source: 'osv' });
    }
  }
  // References only from the CVE record and language advisories; distro records add little beyond trackers.
  for (const rec of records.filter((r) => !/^(DEBIAN|UBUNTU|ALPINE)-/.test(r.id))) {
    for (const ref of rec.references ?? []) {
      references.push({ url: ref.url, type: referenceType(ref.url, ref.type), label: referenceLabel(ref.url), date: referenceDate(ref.url), source: 'osv' });
    }
  }
  for (const rec of records.filter((r) => /^(DEBIAN|UBUNTU|ALPINE)-/.test(r.id))) {
    references.push({ url: `https://osv.dev/vulnerability/${rec.id}`, type: 'tracker', label: `OSV · ${rec.id}`, date: null, source: 'osv' });
  }
  return {
    ids,
    title: main?.summary ?? null,
    published: isoSeconds(main?.published),
    modified: isoSeconds(main?.modified),
    hasRecord: Boolean(main),
    affected,
    references,
    credits,
    osvSeverity: main?.severity ?? [],
  };
}
