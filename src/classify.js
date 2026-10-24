// Compares previous and new data. "editorial" changes need a human to re-check texts; "data-only" do not.
const LEVELS = ['none', 'data-only', 'editorial'];
const key = (a) => `${a.ecosystem}|${a.release ?? ''}|${String(a.package).toLowerCase()}`;
const label = (a) => `${a.ecosystem}${a.release ? ` ${a.release}` : ''} · ${a.package}`;
const base = (eco) => String(eco);

export function classify(prev, next) {
  const items = [];
  const add = (level, cve, message) => items.push({ level, cve, message });

  if (!prev) {
    for (const a of next.advisories) add('editorial', a.id, `Neue CVE in der Watchlist: ${a.id} (${a.aliases.nicknames.join(', ') || 'ohne Spitzname'})`);
    return finish(items);
  }
  if (prev.stand !== next.stand) add('data-only', null, `Stand ${prev.stand} → ${next.stand}`);

  const prevById = new Map(prev.advisories.map((a) => [a.id, a]));
  const nextIds = new Set(next.advisories.map((a) => a.id));
  for (const a of prev.advisories) if (!nextIds.has(a.id)) add('editorial', a.id, `CVE aus der Watchlist entfernt: ${a.id}`);

  for (const n of next.advisories) {
    const p = prevById.get(n.id);
    if (!p) { add('editorial', n.id, `Neue CVE in der Watchlist: ${n.id}`); continue; }

    // KEV
    if (n.kev.exploited === true && p.kev.exploited !== true) add('editorial', n.id, `KEV: jetzt gelistet (aktiv ausgenutzt), aufgenommen am ${n.kev.dateAdded ?? '?'}`);
    else if (n.kev.status !== p.kev.status || n.kev.catalogVersion !== p.kev.catalogVersion) add('data-only', n.id, `KEV: ${p.kev.status ?? p.kev.exploited} → ${n.kev.status ?? n.kev.exploited} (Katalog ${n.kev.catalogVersion ?? '?'})`);

    // CVSS
    const ps = p.cvss?.severity ?? null;
    const ns = n.cvss?.severity ?? null;
    if (ns && ps !== ns) add('editorial', n.id, `CVSS-Stufe: ${ps ?? 'keine'} → ${ns} (${n.cvss.score}, CVSS ${n.cvss.version}, ${n.cvss.source})`);
    else if (JSON.stringify(p.cvss) !== JSON.stringify(n.cvss)) add('data-only', n.id, `CVSS-Details geändert: ${p.cvss?.score ?? '–'} → ${n.cvss?.score ?? '–'}`);

    // EPSS
    if (JSON.stringify(p.epss) !== JSON.stringify(n.epss)) add('data-only', n.id, `EPSS: ${fmtEpss(p.epss)} → ${fmtEpss(n.epss)}`);

    // Nicknames are editorial input; a change means texts may need the new name.
    if (JSON.stringify(p.aliases.nicknames) !== JSON.stringify(n.aliases.nicknames)) add('editorial', n.id, `Spitznamen: ${p.aliases.nicknames.join(', ')} → ${n.aliases.nicknames.join(', ')}`);
    const newIds = n.aliases.ids.filter((id) => !p.aliases.ids.includes(id));
    if (newIds.length) add('data-only', n.id, `Neue Alias-IDs: ${newIds.join(', ')}`);

    // Affected: new ecosystem = editorial, fixStatus changes involving editorial states = editorial.
    const pEco = new Set(p.affected.map((a) => base(a.ecosystem)));
    for (const eco of new Set(n.affected.map((a) => base(a.ecosystem)))) if (!pEco.has(eco)) add('editorial', n.id, `Neues betroffenes Ökosystem: ${eco}`);
    const pAff = new Map(p.affected.map((a) => [key(a), a]));
    const nAff = new Map(n.affected.map((a) => [key(a), a]));
    for (const [k, a] of nAff) {
      const old = pAff.get(k);
      if (!old) { add('data-only', n.id, `Neuer Eintrag: ${label(a)} (${a.affectedRange})`); continue; }
      if (old.fixStatus !== a.fixStatus) {
        const manual = ['pending', 'none', 'via_runtime'];
        const editorial = manual.includes(old.fixStatus) || manual.includes(a.fixStatus) || old.fixStatus === 'fixed';
        add(editorial ? 'editorial' : 'data-only', n.id, `fixStatus ${label(a)}: ${old.fixStatus} → ${a.fixStatus}`);
      }
      const added = a.fixedVersions.filter((v) => !old.fixedVersions.includes(v));
      if (added.length) add('data-only', n.id, `Neue Fix-Version ${label(a)}: ${added.join(', ')}`);
      if ((old.fixRef?.state ?? null) !== (a.fixRef?.state ?? null) && a.fixRef?.state) add('editorial', n.id, `Fix-Beleg ${label(a)}: ${old.fixRef?.state ?? 'unbekannt'} → ${a.fixRef.state} (${a.fixRef.url}); fixStatus in der Watchlist prüfen`);
    }
    for (const [k, a] of pAff) if (!nAff.has(k)) add('data-only', n.id, `Eintrag entfällt: ${label(a)}`);

    // Runtimes
    const pRt = new Map((p.runtimes ?? []).map((r) => [`${r.product}|${r.cycle}`, r]));
    for (const r of n.runtimes ?? []) {
      const old = pRt.get(`${r.product}|${r.cycle}`);
      if (!old) add('editorial', n.id, `Neue Runtime-Linie: ${r.product} ${r.cycle} (${r.status})`);
      else if (old.status !== r.status) add('editorial', n.id, `Runtime ${r.product} ${r.cycle}: ${old.status} → ${r.status}`);
      else if (old.eol !== r.eol || old.latest !== r.latest) add('data-only', n.id, `Runtime ${r.product} ${r.cycle}: EOL/Latest aktualisiert (${r.eol ?? '–'}, ${r.latest ?? '–'})`);
    }

    // References, timeline, credits, dates
    const pRefs = new Set(p.references.map((r) => r.url));
    const newRefs = n.references.filter((r) => !pRefs.has(r.url));
    if (newRefs.length) add('data-only', n.id, `Neue Quellen: ${newRefs.length} (${newRefs.slice(0, 3).map((r) => r.url).join(', ')}${newRefs.length > 3 ? ', …' : ''})`);
    const nRefs = new Set(n.references.map((r) => r.url));
    const goneRefs = p.references.filter((r) => !nRefs.has(r.url));
    if (goneRefs.length) add('data-only', n.id, `Quellen entfallen: ${goneRefs.length}`);
    if (JSON.stringify(p.timeline) !== JSON.stringify(n.timeline)) add('data-only', n.id, 'Timeline aktualisiert');
    if (JSON.stringify(p.credits) !== JSON.stringify(n.credits)) add('data-only', n.id, 'Credits aktualisiert');
    if (p.modified !== n.modified) add('data-only', n.id, `modified: ${p.modified} → ${n.modified}`);

    // Source health
    for (const [name, s] of Object.entries(n.sources ?? {})) {
      const ps2 = p.sources?.[name]?.status;
      if (s.status !== 'ok' && ps2 !== s.status) add('data-only', n.id, `Quelle ${name}: ${s.status}${s.lastError ? ` (${s.lastError})` : ''}`);
    }
  }
  return finish(items);
}

function fmtEpss(e) {
  return e ? `${e.score} (Perzentil ${e.percentile}, ${e.date})` : 'kein Wert';
}

function finish(items) {
  const level = items.reduce((l, i) => (LEVELS.indexOf(i.level) > LEVELS.indexOf(l) ? i.level : l), 'none');
  return { level, items };
}

/** Counts affected entries per ecosystem, e.g. { Debian: 6, PyPI: 2 }. */
export function affectedCounts(advisory) {
  const counts = {};
  for (const a of advisory.affected) counts[a.ecosystem] = (counts[a.ecosystem] ?? 0) + 1;
  return counts;
}

/** Markdown for PR bodies. */
export function summaryMarkdown(result, next) {
  const lines = [];
  const editorial = result.items.filter((i) => i.level === 'editorial');
  const dataOnly = result.items.filter((i) => i.level === 'data-only');
  lines.push(`## 2shell-Daten: ${result.level === 'editorial' ? 'redaktionelle Prüfung nötig' : result.level === 'data-only' ? 'nur Datenänderungen' : 'keine Änderung'}`);
  lines.push('');
  lines.push(`Stand: \`${next.stand}\` (UTC)`);
  lines.push('');
  lines.push('| CVE | CVSS | KEV | EPSS | Betroffene Einträge | Quellen |');
  lines.push('|---|---|---|---|---|---|');
  for (const a of next.advisories) {
    const cvss = a.cvss ? `${a.cvss.score} ${a.cvss.severity} (v${a.cvss.version})` : 'keine Angabe';
    const kev = a.kev.status === 'listed' ? `gelistet seit ${a.kev.dateAdded}` : a.kev.status === 'not_listed' ? 'nicht gelistet' : 'unbekannt';
    const epss = a.epss ? `${a.epss.score} / P ${a.epss.percentile}` : 'kein Wert';
    const counts = Object.entries(affectedCounts(a)).map(([k, v]) => `${k} ${v}`).join(', ') || '–';
    const src = Object.entries(a.sources ?? {}).filter(([, s]) => s.status !== 'ok').map(([k, s]) => `${k}: ${s.status}`).join(', ') || 'alle ok';
    lines.push(`| ${a.id} | ${cvss} | ${kev} | ${epss} | ${counts} | ${src} |`);
  }
  lines.push('');
  if (editorial.length) {
    lines.push('### Text prüfen');
    lines.push('');
    lines.push('Diese Änderungen berühren redaktionelle Aussagen. Erst mergen, wenn die Texte geprüft und freigegeben sind.');
    lines.push('');
    for (const i of editorial) lines.push(`- [ ] ${i.cve ? `**${i.cve}**: ` : ''}${i.message}`);
    lines.push('');
    lines.push('<details><summary>Textbausteine (Entwurf, nicht freigegeben)</summary>');
    lines.push('');
    for (const i of editorial) {
      const adv = next.advisories.find((a) => a.id === i.cve);
      const path = adv?.editorial?.markdownPath ?? '(noch kein Text)';
      lines.push(`- \`${path}\`: TODO Absatz zu „${i.message}“ ergänzen oder anpassen. Quelle verlinken.`);
    }
    lines.push('');
    lines.push('</details>');
    lines.push('');
  }
  if (dataOnly.length) {
    lines.push('<details><summary>Datenänderungen (' + dataOnly.length + ')</summary>');
    lines.push('');
    for (const i of dataOnly) lines.push(`- ${i.cve ? `${i.cve}: ` : ''}${i.message}`);
    lines.push('');
    lines.push('</details>');
    lines.push('');
  }
  lines.push('_Automatisch erzeugt von `npm run refresh`. Nie automatisch mergen._');
  return lines.join('\n') + '\n';
}

/**
 * Guard for auto-merge: only a pure data-only result may be auto-merged.
 * Anything editorial (or an empty/unknown result) must go through a human.
 */
export function autoMergeAllowed(result) {
  if (!result || result.level !== 'data-only') return false;
  if (!Array.isArray(result.items) || result.items.length === 0) return false;
  return result.items.every((i) => i.level === 'data-only');
}
