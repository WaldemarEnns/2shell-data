// Staleness thresholds per source (hours) and the global banner threshold. Exposed in data.meta for the UI.
export const STALE_AFTER_HOURS = {
  osv: 12,
  nvd: 12,
  ghsa: 12,
  cisaKev: 12,
  vendor: 12,
  firstEpss: 48,
  endoflife: 168,
};
export const BANNER_STALE_AFTER_HOURS = 24;
export const REFRESH_INTERVAL_HOURS = 6;
export const PER_CVE_SOURCES = ['osv', 'nvd', 'ghsa', 'cisaKev', 'firstEpss'];
