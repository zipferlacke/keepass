/**
 * home.js — die Übersicht.
 *
 * Oben die Kacheln (wie viele Einträge, Passkeys, Codes, Dateien, Funde),
 * darunter die zuletzt benutzten Einträge als kleine Tabelle. Die Kacheln
 * führen in die passende Ansicht, mit gesetztem Filter.
 *
 * Dazu die Schlagwortleiste, die über der Einträgeliste steht — sie
 * gehört zur selben Auswahl und wird deshalb hier gezeichnet.
 */

import * as vault from '../data/vault.js';
import * as settings from '../data/settings.js';
import { state, $, $$, esc } from '../core/state.js';
import { hasFiles, usageMap, formatDate } from '../core/entries.js';
import { zeichne } from '../core/render.js';
import { showView } from '../core/navigation.js';
import { countProblems } from './checkup.js';
import { renderEntryTable, wireEntryRows } from './entries.js';
import { t } from '../core/i18n.js';

export function renderTags() {
  const tags = vault.allTags();
  const bar = $('#tagbar');

  if (!tags.length) { bar.innerHTML = ''; return; }

  bar.innerHTML = tags
    .map(t => `<button class="tag" data-tag="${esc(t)}" aria-pressed="${state.tag === t}">${esc(t)}</button>`)
    .join('');

  bar.querySelectorAll('.tag').forEach(btn => btn.addEventListener('click', () => {
    // Nochmaliger Klick auf den aktiven Tag hebt den Filter auf
    state.tag = state.tag === btn.dataset.tag ? null : btn.dataset.tag;
    renderTags();
    zeichne('einträge');
  }));
}

export function renderHome() {
  const pwCheck = settings.get('checks.passwordBreach', true);
  const mailCheck = settings.get('checks.emailBreach', true);
  const problems = countProblems();

  const einträge = n => t('uebersicht.kacheln.anzahl', { n });

  const tiles = [
    { view: 'passwords', icon: 'key', name: t('uebersicht.kacheln.eintraege'), count: einträge(state.entries.length) },
    { view: 'passwords', icon: 'passkey', name: t('uebersicht.kacheln.passkeys'), count: einträge(state.entries.filter(e => e.passkey).length), kind: 'passkey' },
    { view: 'totp', icon: 'timer', name: t('uebersicht.kacheln.totp'), count: t('uebersicht.kacheln.codes', { n: state.entries.filter(e => e.hasTotp).length }) },
    { view: 'passwords', icon: 'folder_zip', name: t('uebersicht.kacheln.dateien'), count: einträge(state.entries.filter(hasFiles).length), kind: 'files' }
  ];

  if (pwCheck || mailCheck) {
    tiles.push({
      view: 'security', icon: 'gpp_maybe', name: t('uebersicht.kacheln.sicherheit'),
      count: state.lastCheck ? t('uebersicht.kacheln.funde', { n: problems }) : t('uebersicht.kacheln.ungeprueft'),
      variant: problems > 0 ? 'alert' : null
    });
  }

  $('#tile-grid').innerHTML = tiles.map(t => `
    <button class="tile" data-view="${t.view}" ${t.kind ? `data-kind="${t.kind}"` : ''} ${t.variant ? `data-variant="${t.variant}"` : ''}>
      <span class="msr">${t.icon}</span>
      <span class="tile-name">${t.name}</span>
      <span class="tile-count">${t.count}</span>
    </button>`).join('');

  $$('#tile-grid .tile').forEach(btn => btn.addEventListener('click', () => {
    state.kindFilter = btn.dataset.kind ?? null;
    showView(btn.dataset.view);
  }));

  const usage = usageMap();
  const lastUsed = e => Math.max(usage[e.id]?.at ?? 0, Date.parse(e.accessed ?? '') || 0);

  const recent = state.entries
    .filter(e => !e.recycled)
    .sort((a, b) => lastUsed(b) - lastUsed(a))
    .slice(0, 6);
  renderEntryTable($('#recent-list'), recent, { variant: 'compact' });
}

/* =========================================================
   Zuletzt genutzt
   ---------------------------------------------------------
   KeePass führt dafür „LastAccessTime" in der Datei — die zu setzen hieße
   aber, bei jedem Kopieren die ganze Datenbank neu zu schreiben, und das
   bei einer Datei, die über Nextcloud auch KeePassXC anfasst. Deshalb
   merkt sich das Programm die Nutzung selbst, pro Datenbank in
   settings.json, und nimmt den Wert aus der Datei nur dazu.

   Als genutzt zählt: Eintrag öffnen, Benutzername/Passwort/TOTP kopieren,
   Anhang ansehen und jede erlaubte Abfrage über die Browser-Erweiterung
   (der Kern meldet sie mit `entries-used`).

   Gespeichert wird je Eintrag
     at     der letzte Zeitpunkt — bleibt, auch wenn er älter als 7 Tage ist
     week   alle Zeitpunkte der letzten 7 Tage, für die Statistik
   In settings.json stehen dabei nur UUIDs und Zeitpunkte, keine Namen.
   ========================================================= */
