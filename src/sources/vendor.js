// "vendor": checks the state of GitHub pull requests used as fixRef in the watchlist (open / merged / closed).
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
