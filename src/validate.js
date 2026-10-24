import { readFileSync } from 'node:fs';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

const load = (rel) => JSON.parse(readFileSync(new URL(rel, import.meta.url), 'utf8'));
export const dataSchema = load('../schema/2shell.schema.json');
export const watchlistSchema = load('../schema/watchlist.schema.json');

function makeAjv() {
  const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false, allowUnionTypes: true });
  addFormats(ajv);
  ajv.addKeyword({ keyword: 'x-visible' });
  ajv.addKeyword({ keyword: 'x-source' });
  ajv.addSchema(dataSchema);
  return ajv;
}

const ajv = makeAjv();
const dataValidator = ajv.getSchema(dataSchema.$id);
const watchlistValidator = ajv.compile(watchlistSchema);

function run(fn, value) {
  const ok = fn(value);
  return { ok, errors: ok ? [] : fn.errors.map((e) => `${e.instancePath || '/'} ${e.message}${e.params ? ' ' + JSON.stringify(e.params) : ''}`) };
}

export const validateData = (data) => run(dataValidator, data);
export const validateWatchlist = (wl) => run(watchlistValidator, wl);
