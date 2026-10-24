#!/usr/bin/env node
// Usage: node bin/refresh.js [--data data/2shell.json] [--summary out.md] [--classification out.json] [--dry-run]
import { readFileSync, writeFileSync, existsSync, appendFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { parseArgs } from 'node:util';
import { refresh } from '../src/refresh.js';
import { AllSourcesFailedError } from '../src/build.js';
import { autoMergeAllowed } from '../src/classify.js';

const { values } = parseArgs({
  options: {
    watchlist: { type: 'string', default: 'watchlist.json' },
    data: { type: 'string', default: 'data/2shell.json' },
    summary: { type: 'string' },
    classification: { type: 'string' },
    'dry-run': { type: 'boolean', default: false },
  },
});

const readJson = (p) => JSON.parse(readFileSync(p, 'utf8'));
const watchlist = readJson(values.watchlist);
const previous = existsSync(values.data) ? readJson(values.data) : null;

let res;
try {
  res = await refresh({ watchlist, previous, env: process.env });
} catch (err) {
  if (err instanceof AllSourcesFailedError) {
    console.error(err.message);
    setOutput('level', 'none');
    setOutput('automerge', 'false');
    process.exit(0);
  }
  console.error(err.message);
  process.exit(1);
}

const { data, classification, summary } = res;
if (!values['dry-run']) {
  mkdirSync(dirname(values.data), { recursive: true });
  writeFileSync(values.data, JSON.stringify(data, null, 2) + '\n');
}
if (values.summary) writeFileSync(values.summary, summary);
if (values.classification) writeFileSync(values.classification, JSON.stringify(classification, null, 2) + '\n');

for (const [name, s] of Object.entries(data.sources)) console.log(`source ${name.padEnd(10)} ${s.status.padEnd(9)} fetchedAt=${s.fetchedAt ?? '-'}${s.lastError ? ` error=${s.lastError}` : ''}`);
console.log(`classification: ${classification.level} (${classification.items.length} changes)`);
setOutput('level', classification.level);
setOutput('automerge', String(autoMergeAllowed(classification)));
console.log(`auto-merge allowed: ${autoMergeAllowed(classification)}`);

function setOutput(k, v) {
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `${k}=${v}\n`);
}
