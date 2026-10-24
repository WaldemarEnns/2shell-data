#!/usr/bin/env node
// Dependency-free lint: syntax check for all JS, JSON parse check, watchlist and data validation, no secrets-like strings.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { validateData, validateWatchlist } from '../src/validate.js';

const root = new URL('..', import.meta.url).pathname;
const skip = new Set(['node_modules', '.git']);
const files = [];
(function walk(d) {
  for (const f of readdirSync(d)) {
    if (skip.has(f)) continue;
    const p = join(d, f);
    if (statSync(p).isDirectory()) walk(p);
    else files.push(p);
  }
})(root);

let failed = 0;
const fail = (msg) => { failed++; console.error(`✗ ${msg}`); };

for (const f of files.filter((f) => f.endsWith('.js'))) {
  try { execFileSync(process.execPath, ['--check', f], { stdio: 'pipe' }); } catch (e) { fail(`${f}: ${e.stderr}`); }
  const src = readFileSync(f, 'utf8');
  if (/console\.log\(.*(TOKEN|API_KEY)/.test(src)) fail(`${f}: logs a secret-looking variable`);
}
for (const f of files.filter((f) => f.endsWith('.json'))) {
  try { JSON.parse(readFileSync(f, 'utf8')); } catch (e) { fail(`${f}: ${e.message}`); }
}
const wl = validateWatchlist(JSON.parse(readFileSync(join(root, 'watchlist.json'), 'utf8')));
if (!wl.ok) fail(`watchlist.json: ${wl.errors.join('; ')}`);
try {
  const v = validateData(JSON.parse(readFileSync(join(root, 'data/2shell.json'), 'utf8')));
  if (!v.ok) fail(`data/2shell.json: ${v.errors.join('; ')}`);
} catch (e) {
  if (e.code !== 'ENOENT') fail(`data/2shell.json: ${e.message}`);
}
if (failed) process.exit(1);
console.log(`lint ok (${files.length} files)`);
