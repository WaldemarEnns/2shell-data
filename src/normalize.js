// Shared helpers that turn source-specific shapes into the output shape.

/** ISO timestamp, UTC, second precision ("2026-10-22T13:35:41Z"). Accepts NVD timestamps without zone (they are UTC). */
export function isoSeconds(value) {
  if (!value) return null;
  let s = String(value);
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/.test(s)) s += 'Z';
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return null;
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

export function isoDate(value) {
  const s = isoSeconds(value);
  return s ? s.slice(0, 10) : null;
}

const ECOSYSTEM_MAP = {
  npm: 'npm', pypi: 'PyPI', pip: 'PyPI', packagist: 'Packagist', composer: 'Packagist',
  debian: 'Debian', ubuntu: 'Ubuntu', alpine: 'Alpine', rubygems: 'RubyGems', nuget: 'NuGet',
};

/** "Debian:12" -> { ecosystem: "Debian", release: "12" }; "Ubuntu:Pro:14.04:LTS" -> release "Pro:14.04:LTS". */
export function splitEcosystem(raw) {
  const [base, ...rest] = String(raw).split(':');
  const ecosystem = ECOSYSTEM_MAP[base.toLowerCase()] ?? null;
  return { ecosystem, release: rest.length ? rest.join(':') : null };
}

/** OSV range events -> readable range, plus the list of fixed versions. */
export function describeRanges(ranges = []) {
  const parts = [];
  const fixed = [];
  for (const range of ranges) {
    if (range.type === 'GIT') continue;
    let intro = null;
    for (const ev of range.events ?? []) {
      if ('introduced' in ev) {
        if (intro !== null) parts.push(openRange(intro));
        intro = ev.introduced;
      } else if ('fixed' in ev) {
        fixed.push(ev.fixed);
        parts.push(intro && intro !== '0' ? `>= ${intro}, < ${ev.fixed}` : `< ${ev.fixed}`);
        intro = null;
      } else if ('last_affected' in ev) {
        parts.push(intro && intro !== '0' ? `>= ${intro}, <= ${ev.last_affected}` : `<= ${ev.last_affected}`);
        intro = null;
      } else if ('limit' in ev) {
        parts.push(intro && intro !== '0' ? `>= ${intro}, < ${ev.limit}` : `< ${ev.limit}`);
        intro = null;
      }
    }
    if (intro !== null) parts.push(openRange(intro));
  }
  return { affectedRange: parts.length ? parts.join(' | ') : 'keine Angabe', fixedVersions: fixed };
}

function openRange(intro) {
  return intro === '0' ? 'alle Versionen (kein Fix gelistet)' : `>= ${intro} (kein Fix gelistet)`;
}

const OSV_REF_TYPES = {
  ADVISORY: 'advisory', FIX: 'fix', PACKAGE: 'tracker', REPORT: 'tracker', ARTICLE: 'news',
  WEB: 'analysis', EVIDENCE: 'analysis', INTRODUCED: 'fix', GIT: 'fix', DETECTION: 'analysis', DISCUSSION: 'analysis',
};

/** Reference type from URL first (more reliable), then from the source's own type. */
export function referenceType(url, sourceType) {
  const u = String(url);
  if (/nvd\.nist\.gov\/vuln|cve\.org\/CVERecord|cvelistV5/.test(u)) return 'cve';
  if (/github\.com\/advisories\/GHSA|\/security\/advisories\/GHSA|osv\.dev\/vulnerability/.test(u)) return 'advisory';
  if (/\/commit\/|\/pull\/\d+/.test(u)) return 'fix';
  if (/\/releases\/tag\/|\/releases\/|pypi\.org\/project/.test(u)) return 'release';
  if (/security-tracker\.debian|lists\.debian\.org|ubuntu\.com\/security|security\.alpinelinux|advisory-database\/tree/.test(u)) return 'tracker';
  if (/nodejs\.org\/en\/blog\/vulnerability|php\.net\/|thephp\.foundation/.test(u)) return 'vendor';
  if (/openwall\.com\/lists\/oss-security/.test(u)) return 'analysis';
  return OSV_REF_TYPES[String(sourceType ?? '').toUpperCase()] ?? 'analysis';
}

/** Neutral display label derived from the URL. Editorial labels in the watchlist take precedence. */
export function referenceLabel(url) {
  let u;
  try { u = new URL(url); } catch { return String(url); }
  const host = u.hostname.replace(/^www\./, '');
  const p = u.pathname;
  let m;
  if (host === 'github.com' && (m = p.match(/^\/([^/]+\/[^/]+)\/security\/advisories\/(GHSA(?:-[a-z0-9]{4}){3})/i))) return `${m[1]} · Advisory ${m[2]}`;
  if ((m = p.match(/(GHSA(?:-[a-z0-9]{4}){3})/i))) return `GitHub Advisory ${m[1]}`;
  if (host === 'openwall.com' && (m = p.match(/^\/lists\/([^/]+)\/(\d{4})\/(\d{1,2})\/(\d{1,2})\/(\d+)/))) return `${m[1]} · ${m[4].padStart(2, '0')}.${m[3].padStart(2, '0')}.${m[2]} · Nachricht ${m[5]}`;
  if (host === 'lists.debian.org' && (m = p.match(/^\/([^/]+)\/(\d{4})\/(\d{2})\/(msg\d+)/))) return `Debian ${m[1]} · ${m[3]}/${m[2]} · ${m[4]}`;
  if (host === 'github.com' && (m = p.match(/^\/CVEProject\/cvelistV5\/.*\/(CVE-\d{4}-\d+)\.json$/))) return `CVE List V5 · ${m[1]}`;
  if (host === 'pypi.org' && (m = p.match(/^\/project\/([^/]+)(?:\/([^/]+))?/))) return `PyPI · ${m[1]}${m[2] ? ` ${m[2]}` : ''}`;
  if (host === 'osv.dev' && (m = p.match(/^\/vulnerability\/([^/]+)/))) return `OSV · ${m[1]}`;
  if (host === 'nvd.nist.gov' && (m = p.match(/(CVE-\d{4}-\d+)/))) return `NVD · ${m[1]}`;
  if (host === 'cve.org' && (m = u.search.match(/(CVE-\d{4}-\d+)/))) return `CVE.org · ${m[1]}`;
  if ((m = p.match(/^\/([^/]+\/[^/]+)\/commit\/([0-9a-f]{7})/))) return `${m[1]} · Commit ${m[2]}`;
  if ((m = p.match(/^\/([^/]+\/[^/]+)\/pull\/(\d+)/))) return `${m[1]} · PR #${m[2]}`;
  if ((m = p.match(/^\/([^/]+\/[^/]+)\/releases\/tag\/([^/]+)/))) return `${m[1]} · Release ${decodeURIComponent(m[2])}`;
  if ((m = p.match(/\/vulns\/([^/]+)\/([A-Z]+-\d{4}-\d+)/))) return `PyPA Advisory · ${m[2]} (${m[1]})`;
  if (host === 'github.com' && (m = p.match(/^\/([^/]+\/[^/]+)\/?$/))) return `GitHub · ${m[1]}`;
  const tail = p.split('/').filter(Boolean).slice(-1)[0];
  return tail ? `${host} · ${decodeURIComponent(tail).slice(0, 80)}` : host;
}

export function normalizeUrl(url) {
  return String(url).trim().replace(/\/+$/, '');
}

/** CVSS severity bands (identical for 3.1 and 4.0). */
export function severityFromScore(score) {
  if (score == null) return null;
  if (score === 0) return 'NONE';
  if (score < 4) return 'LOW';
  if (score < 7) return 'MEDIUM';
  if (score < 9) return 'HIGH';
  return 'CRITICAL';
}

const CVSS_SOURCE_NAMES = {
  'nvd@nist.gov': 'NVD',
  'cve-coordination@google.com': 'Google (CNA)',
  'security@php.net': 'PHP (CNA)',
  'security-advisories@github.com': 'GitHub (CNA)',
};

export function cvssSourceName(source) {
  return CVSS_SOURCE_NAMES[source] ?? source ?? 'unbekannt';
}

const OSV_CREDIT_ROLES = { FINDER: 'reporter', REPORTER: 'reporter', REMEDIATION_DEVELOPER: 'fix', REMEDIATION_REVIEWER: 'fix', ANALYST: 'analysis' };
const GHSA_CREDIT_ROLES = { finder: 'reporter', reporter: 'reporter', remediation_developer: 'fix', remediation_reviewer: 'fix', analyst: 'analysis' };
export const creditRole = (type, kind) => (kind === 'osv' ? OSV_CREDIT_ROLES : GHSA_CREDIT_ROLES)[kind === 'osv' ? String(type).toUpperCase() : String(type).toLowerCase()] ?? null;

/** Date that is part of the URL itself (mailing-list archives). Null if the URL carries no date. */
export function referenceDate(url) {
  const m = String(url).match(/openwall\.com\/lists\/[^/]+\/(\d{4})\/(\d{1,2})\/(\d{1,2})\//);
  return m ? `${m[1]}-${m[2].padStart(2, '0')}-${m[3].padStart(2, '0')}` : null;
}
