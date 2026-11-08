/**
 * state.js — was die ganze Oberfläche gemeinsam weiß.
 *
 * Ein einziges Objekt statt vieler verstreuter Variablen: Welche Ansicht
 * offen ist, welche Einträge geladen sind, wonach gesucht wird, was der
 * Sicherheitscheck gefunden hat. Jede Seite liest hier und schreibt hier;
 * gezeichnet wird daraus in `core/render.js`.
 *
 * Dazu die drei Handgriffe, die jede Seite braucht: ein Element suchen,
 * mehrere suchen, und Text so entschärfen, dass er gefahrlos in HTML darf.
 */

import { t } from './i18n.js';

/* =========================================================
   Zustand
   ========================================================= */
export const state = {
  view: 'home',
  entries: [],
  search: '',
  tag: null,
  kindFilter: null,
  expanded: new Set(),
  /** Papierkorb unter der Liste aufgeklappt? */
  binOpen: false,
  /** Ausgeschnittene Einträge (Kennungen), die auf das Einfügen warten. */
  cut: [],
  pwned: new Map(),
  reused: new Set(),
  strength: new Map(),
  codes: new Map(),
  emailFindings: [],
  checkRunning: false,
  lastCheck: null,
  dialogAttachments: [],
  secretEdits: null,
  locked: true,
  /** Was der Kern zum Entsperren anbietet — wird beim Start abgefragt. */
  unlock: { password: true, pin: false, biometric: false, device: false, deviceAvailable: false, deviceLabel: null },
  /** Welcher Eintrag gerade im Dialog offen ist — für „zuletzt genutzt". */
  dialogEntryId: null
};

export const $ = sel => document.querySelector(sel);
export const $$ = sel => [...document.querySelectorAll(sel)];
export const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

/** Anzeige für ein gesetztes, noch nicht geladenes Geheimnis. */
export const SECRET_MASK = '•••••';

/** Titel oben über der Ansicht — in der gewählten Sprache. */
export function viewTitle(view) {
  // i18n: navigation.titel.home navigation.titel.passwords navigation.titel.totp navigation.titel.security navigation.titel.settings
  return ['home', 'passwords', 'totp', 'security', 'settings'].includes(view) ? t(`navigation.titel.${view}`) : 'WKeePass';
}
