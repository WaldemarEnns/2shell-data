# 2shell-data

Kleine, kuratierte Datenpipeline für die aktuellen „2shell“-Sicherheitslücken. Sie liefert `data/2shell.json` für statische Advisory-Seiten (php-check.waldemarenns.de und eine geplante Übersichtsseite).

**Keine allgemeine CVE-Datenbank.** Erfasst wird nur, was in [`watchlist.json`](watchlist.json) steht:

| CVE | Name | Kurz |
|---|---|---|
| CVE-2026-111497 | Node2Shell / HTTP2Shell | Out-of-bounds write im Brotli-Decoder 1.0.3–1.2.0 (Node.js, Bun, Python Brotli/brotlicffi, gebündelte Kopien) |
| CVE-2026-109618 | PHP2Shell | PHP: nicht initialisierter Request-Speicher nach OOM-longjmp |
| CVE-2026-109619 | PHP2Shell | PHP: globaler Zustand zeigt auf freigegebenen Request-Speicher |

## Quellen (alle kostenlos, ohne Login)

| Schlüssel | Quelle | Liefert | gilt als veraltet nach |
|---|---|---|---|
| `osv` | [OSV.dev API](https://google.github.io/osv.dev/api/) | Aliase, betroffene/gefixte Versionen (npm, PyPI, Packagist, Debian, Ubuntu, Alpine), Referenzen, Credits | 12 h |
| `nvd` | [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities) | CVSS 4.0/3.1, Veröffentlichung, Referenzen | 12 h |
| `ghsa` | [GitHub Advisory Database](https://docs.github.com/en/rest/security-advisories/global-advisories) | GHSA, Paketbereiche, CVSS-Fallback | 12 h |
| `cisaKev` | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | aktiv ausgenutzt: gelistet / nicht gelistet / unbekannt | 12 h |
| `firstEpss` | [FIRST EPSS](https://www.first.org/epss/api) | Ausnutzungswahrscheinlichkeit (täglich) | 48 h |
| `endoflife` | [endoflife.date](https://endoflife.date/docs/api/v1/) | EOL-Daten für Node.js, PHP, Python, Bun | 168 h |
| `vendor` | GitHub-API (Pull Requests) | Status der Fix-Belege (`fixRef`), z. B. kjdev/php-ext-brotli#105 | 12 h |

Fix-Versionen der Runtimes (Node.js 22.23.4 / 24.22.1 / 26.12.1, Bun 1.4.4, PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12) stehen von Hand in der Watchlist, jeweils mit Herstellerlink. Diese Versionen tauchen in OSV/GHSA nicht als Paket auf.

Optional: `NVD_API_KEY` (höheres Rate-Limit) und `GITHUB_TOKEN`. Beide nur als Umgebungsvariable bzw. Actions-Secret, nie im Repo. Ohne Key wartet der Lauf 6,5 s zwischen NVD-Abfragen (öffentliches Limit 5 Anfragen pro 30 s).

## Ablauf

```
watchlist.json ─┐
                ├─> bin/refresh.js ─> Schema-Prüfung ─> data/2shell.json
vorheriger Stand┘        │                                  │
                         └──── Klassifizierung (alt vs. neu) ┴─> PR-Text (Markdown)
```

- **Zeitplan:** GitHub Action [`refresh.yml`](.github/workflows/refresh.yml) alle 6 Stunden (`0 */6 * * *`, UTC) und manuell per `workflow_dispatch`.
- **`stand`** ist der Zeitpunkt des letzten erfolgreichen Laufs. Schlagen alle Quellen fehl, wird nichts geschrieben.
- **Ausfall einer Quelle:** Der letzte gute Wert bleibt stehen, nichts wird geleert. `sources.<name>.fetchedAt` bleibt auf dem letzten Erfolg, `lastError` nennt den Fehler. `status` ist `ok`, solange der letzte Erfolg jünger als die Schwelle oben ist, danach `veraltet`; `fehlt`, wenn es nie einen Erfolg gab. Die Schwellen und die Banner-Schwelle (24 h für das globale `stand`) stehen in `meta`, damit die Seite sie anwenden kann.
- **KEV** ist dreiwertig: `kev.status` = `listed` / `not_listed` / `unknown` (`kev.exploited` true / false / null).
- **Titel sind intern.** `title` ist ein englischer Kurztitel aus OSV bzw. der NVD-Beschreibung und wird nicht angezeigt. Die sichtbaren deutschen Überschriften schreibt die Redaktion (Desi) in den Texten unter `editorial.markdownPath`. Ebenso redaktionell und derzeit leer: `exploitation` (PoC, Laborbeweis) und Einträge mit `role: exposure_path` (z. B. Express 5 / body-parser).
- **Keine Ampel in den Daten.** Die Seite leitet Farben aus `fixStatus` und `runtimes[].status` ab.

## Redaktionelle Regel

Ein Datenlauf veröffentlicht nie selbst und überschreibt nie Texte.

- **Nur Daten** (`data-only`): EPSS, `stand`, neue Fix-Versionen, Referenzen, Quellenstatus → Commit auf Branch `data/refresh`, PR „data: refresh“ wird angelegt oder aktualisiert.
- **Redaktionell** (`editorial`): neue CVE in der Watchlist, KEV wird „gelistet“, CVSS-Stufe ändert sich, neues betroffenes Ökosystem oder neue Runtime-Linie, Statuswechsel einer Runtime, `fixStatus`-Wechsel von/zu `pending`/`none` oder weg von `fixed`, Statuswechsel eines Fix-Belegs (z. B. PR gemergt) → **Entwurfs-PR** auf `data/editorial` mit Label `editorial` und Checkliste „Text prüfen“.
- Die Action pusht nie auf `main` und merged nie. Gemergt wird von Hand.
- `fixStatus` `pending` und `none` kommen **nur** aus der Watchlist (`manualAffected` oder `fixStatusOverrides`, jeweils mit `fixRef`, `verifiedBy`, `verifiedAt`). Automatisch gibt es nur `fixed` (Quelle nennt eine Fix-Version) oder `unknown` (Quelle nennt keine).

## Dateien

| Pfad | Inhalt |
|---|---|
| `watchlist.json` | CVE-IDs und redaktionelle Angaben: Spitznamen, Runtime-Fix-Tabelle, manuelle Einträge, Overrides, Timeline, Credits, Quellen mit Label |
| `schema/2shell.schema.json` | JSON Schema der Ausgabe (kompatibel zu Desis Entwurf v1, mit `x-visible`/`x-source`) |
| `schema/watchlist.schema.json` | JSON Schema der Watchlist |
| `data/2shell.json` | Ausgabe |
| `src/` | Fetcher (`sources/`), Zusammenführung mit Fallback (`build.js`), Klassifizierung (`classify.js`) |
| `test/` | Tests auf einmal aufgezeichneten echten Antworten (`test/fixtures/http/`; KEV gekürzt) |

## Lokal

```sh
# Node 24.22.1
npm ci
npm test
npm run lint
npm run refresh -- --summary /tmp/summary.md     # Live-Lauf, schreibt data/2shell.json
npm run record-fixtures                          # Fixtures neu aufzeichnen (ohne Token)
```

## Lizenz

MIT, siehe [LICENSE](LICENSE). Die Daten stammen aus den oben genannten Quellen und unterliegen deren Nutzungsbedingungen. Maßgeblich sind immer die verlinkten Herstellerhinweise.
