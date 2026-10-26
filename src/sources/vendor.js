// "vendor": checks the state of GitHub pull requests used as fixRef in the watchlist (open / merged / closed)
// and which releases a registry (PECL) offers, for fixAvailability in the watchlist.
export async function fetchPullState(url, ctx) {
  const m = String(url).match(/^https:\/\/github\.com\/([^/]+)\/([^/]+)\/pull\/(\d+)/);
  if (!m) return null;
  const headers = { accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28' };
  if (ctx.env.GITHUB_TOKEN) headers.authorization = `Bearer ${ctx.env.GITHUB_TOKEN}`;
  const r = await ctx.fetchJson(`https://api.github.com/repos/${m[1]}/${m[2]}/pulls/${m[3]}`, { headers });
  return normalizePullState(r.json);
}

export function normalizePullState(json) {
  if (!json || !json.state) throw new Error('GitHub pull: unexpected response format');
  return json.merged || json.merged_at ? 'merged' : json.state === 'closed' ? 'closed' : 'open';
}

/** All release versions PECL lists for a package (pecl.php.net REST, XML). */
export async function fetchPeclReleases(pkg, ctx) {
  if (!/^[A-Za-z0-9_]+$/.test(String(pkg))) throw new Error(`PECL: invalid package name ${pkg}`);
  const r = await ctx.fetchText(`https://pecl.php.net/rest/r/${String(pkg).toLowerCase()}/allreleases.xml`);
  return parsePeclReleases(r.text);
}

export function parsePeclReleases(xml) {
  const versions = [...String(xml ?? '').matchAll(/<v>\s*([^<\s]+)\s*<\/v>/g)].map((m) => m[1]);
  if (!versions.length) throw new Error('PECL: unexpected response format');
  return versions;
}
