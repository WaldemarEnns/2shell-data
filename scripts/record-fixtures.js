#!/usr/bin/env node
// Captures real API responses once into test/fixtures/http/ so tests run offline.
// The KEV catalog (~1.8 MB) is trimmed to its header, the first 5 entries and any watchlist CVEs.
import { readFileSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { fetchJson, redact } from '../src/http.js';
import { fetchAll } from '../src/fetch-all.js';
import { KEV_URL } from '../src/sources/kev.js';

const dir = new URL('../test/fixtures/http/', import.meta.url);
rmSync(dir, { recursive: true, force: true });
mkdirSync(dir, { recursive: true });
const watchlist = JSON.parse(readFileSync(new URL('../watchlist.json', import.meta.url), 'utf8'));
const ids = new Set(watchlist.advisories.map((a) => a.id));
const index = {};
let n = 0;

async function recordingFetch(url, opts) {
  const res = await fetchJson(url, opts);
  let json = res.json;
  if (url === KEV_URL) {
    json = { ...json, _fixtureNote: 'trimmed: header, first 5 entries, watchlist CVEs', vulnerabilities: json.vulnerabilities.filter((v, i) => i < 5 || ids.has(v.cveID)) };
  }
  const file = `${String(++n).padStart(3, '0')}.json`;
  writeFileSync(new URL(file, dir), JSON.stringify(json, null, 2) + '\n');
  index[redact(url)] = { file, status: res.status };
  return { status: res.status, json };
}

// No tokens while recording: fixtures must reflect public, unauthenticated responses.
await fetchAll(watchlist, { fetchJson: recordingFetch, env: {} });
writeFileSync(new URL('index.json', dir), JSON.stringify({ recordedAt: new Date().toISOString(), responses: index }, null, 2) + '\n');
console.log(`recorded ${n} responses`);
