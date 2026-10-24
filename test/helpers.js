import { readFileSync } from 'node:fs';
import { HttpError } from '../src/http.js';

const dir = new URL('./fixtures/http/', import.meta.url);
const index = JSON.parse(readFileSync(new URL('index.json', dir), 'utf8')).responses;

export const watchlist = JSON.parse(readFileSync(new URL('../watchlist.json', import.meta.url), 'utf8'));
export const clone = (x) => structuredClone(x);
export const noSleep = async () => {};

/** Replays recorded responses. `fail` = list of URL substrings that should fail like a network error. */
export function replayFetch({ fail = [] } = {}) {
  return async (url) => {
    if (fail.some((f) => url.includes(f))) throw new HttpError(url, 503);
    const hit = index[url];
    if (!hit) throw new HttpError(url, 0, `no fixture for ${url}`);
    return { status: hit.status, json: JSON.parse(readFileSync(new URL(hit.file, dir), 'utf8')) };
  };
}

export const SOURCE_URLS = {
  osv: 'api.osv.dev',
  nvd: 'services.nvd.nist.gov',
  ghsa: 'api.github.com/advisories',
  cisaKev: 'cisa.gov',
  firstEpss: 'api.first.org',
  endoflife: 'endoflife.date',
  vendor: 'api.github.com/repos',
};
