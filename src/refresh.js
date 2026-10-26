// One refresh run: fetch, build, validate, classify. Pure apart from the injected fetchJson.
import { fetchAll } from './fetch-all.js';
import { buildData } from './build.js';
import { validateData, validateWatchlist } from './validate.js';
import { classify, summaryMarkdown } from './classify.js';

export async function refresh({ watchlist, previous, fetchJson, fetchText, env, sleep, now = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z') }) {
  const wl = validateWatchlist(watchlist);
  if (!wl.ok) throw new Error(`watchlist.json is invalid:\n${wl.errors.join('\n')}`);
  const results = await fetchAll(watchlist, { fetchJson, fetchText, env, sleep });
  const data = buildData({ watchlist, previous, results, now });
  const v = validateData(data);
  if (!v.ok) {
    const err = new Error(`Output does not match schema/2shell.schema.json:\n${v.errors.join('\n')}`);
    err.data = data;
    throw err;
  }
  const classification = classify(previous, data);
  return { data, results, classification, summary: summaryMarkdown(classification, data) };
}
