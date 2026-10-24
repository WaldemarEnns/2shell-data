// Minimal JSON fetcher with timeout and retry. Returns { status, json } or throws.
export const USER_AGENT = '2shell-data (+https://github.com/WaldemarEnns/2shell-data)';

export class HttpError extends Error {
  constructor(url, status, message) {
    super(message ?? `HTTP ${status} for ${redact(url)}`);
    this.url = redact(url);
    this.status = status;
  }
}

// Never write API keys into errors or fixtures.
export function redact(url) {
  return String(url).replace(/([?&](api_?key|token)=)[^&]+/gi, '$1REDACTED');
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * @param {string} url
 * @param {{headers?: Record<string,string>, timeoutMs?: number, retries?: number, allow404?: boolean}} [opts]
 * @returns {Promise<{status:number, json:any}>}
 */
export async function fetchJson(url, opts = {}) {
  const { headers = {}, timeoutMs = 30000, retries = 2, allow404 = false } = opts;
  let lastErr;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res = await fetch(url, {
        headers: { 'user-agent': USER_AGENT, accept: 'application/json', ...headers },
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (res.status === 404 && allow404) {
        let json = null;
        try { json = await res.json(); } catch { /* empty body */ }
        return { status: 404, json };
      }
      if (res.status === 429 || res.status >= 500) throw new HttpError(url, res.status);
      if (!res.ok) {
        const err = new HttpError(url, res.status);
        err.fatal = true;
        throw err;
      }
      return { status: res.status, json: await res.json() };
    } catch (err) {
      lastErr = err;
      if (err.fatal || attempt === retries) break;
      await sleep(1500 * (attempt + 1));
    }
  }
  throw lastErr instanceof HttpError ? lastErr : new HttpError(url, 0, `${lastErr?.name ?? 'Error'}: ${lastErr?.message} (${redact(url)})`);
}
