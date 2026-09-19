/**
 * settings.js
 * ---------------------------------------------------------------
 * Hält die Einstellungen als JSON-Objekt. Gelesen und geschrieben wird
 * über den Kern (`settings_read` / `settings_write`), der die Datei an
 * der plattformüblichen Stelle ablegt — unter Linux also in
 * `~/.config/de.wuefl.wkeepass/settings.json`.
 *
 * Die Standardwerte kommen aus `config/settings.default.json` und stehen
 * nur dort. Fehlt die Datei, bricht der Start hörbar ab, statt still mit
 * halben Werten weiterzulaufen.
 */

import { invoke } from './platform.js';

const DEFAULTS_URL = './config/settings.default.json';

const storage = {
  read: () => invoke('settings_read'),
  write: obj => invoke('settings_write', { json: JSON.stringify(obj, null, 2) })
};

let defaults = null;
let current = null;
const listeners = new Set();

function deepMerge(base, patch) {
  const out = structuredClone(base);
  for (const [k, v] of Object.entries(patch ?? {})) {
    out[k] = (v && typeof v === 'object' && !Array.isArray(v) && typeof out[k] === 'object')
      ? deepMerge(out[k], v)
      : structuredClone(v);
  }
  return out;
}

async function loadDefaults() {
  if (defaults) return defaults;

  const res = await fetch(DEFAULTS_URL, { cache: 'no-store' });
  if (!res.ok) throw new Error(`settings.default.json nicht lesbar (${res.status}).`);
  defaults = await res.json();
  return defaults;
}

export async function initSettings() {
  const def = await loadDefaults();
  const stored = await storage.read();
  current = stored ? deepMerge(def, stored) : structuredClone(def);
  await storage.write(current);
  return current;
}

/**
 * Liest die gespeicherten Einstellungen neu, ohne zu schreiben — für das
 * kleine Browser-Fenster, das lange lebt, während das Hauptfenster
 * Einstellungen ändert.
 */
export async function reloadSettings() {
  const def = await loadDefaults();
  const stored = await storage.read();
  current = stored ? deepMerge(def, stored) : structuredClone(def);
  return current;
}

export function getSettings() {
  return current ?? defaults ?? {};
}

/** Pfad-Zugriff: get('checks.emailBreachCheck.enabled') */
export function get(path, fallback = undefined) {
  return path.split('.').reduce((o, k) => (o == null ? undefined : o[k]), getSettings()) ?? fallback;
}

/** Setzt einen Wert per Pfad und schreibt settings.json neu.
 *  { silent: true } unterdrückt die Change-Benachrichtigung — für
 *  reine UI-Zustände wie aufgeklappte Ordner, die kein Neu-Rendern brauchen. */
export async function set(path, value, { silent = false } = {}) {
  const keys = path.split('.');
  const last = keys.pop();
  let node = current;
  for (const k of keys) {
    if (typeof node[k] !== 'object' || node[k] === null) node[k] = {};
    node = node[k];
  }
  if (JSON.stringify(node[last]) === JSON.stringify(value)) return;  // nichts geändert
  node[last] = value;
  await storage.write(current);
  if (!silent) emit();
}

/** Kopie der Standardwerte — z. B. um nur einen Teilbereich zurückzusetzen. */
export async function resetSettings() {
  const def = await loadDefaults();
  // Vollständig ersetzen statt zu mischen — sonst überleben Schlüssel
  // aus einer älteren Fassung der Datei.
  current = structuredClone(def);
  await storage.write(current);
  emit();
  return current;
}

export async function importSettings(json) {
  const def = await loadDefaults();
  const parsed = typeof json === 'string' ? JSON.parse(json) : json;
  if (!parsed || typeof parsed !== 'object') throw new Error('Keine gültige Konfiguration.');
  current = deepMerge(def, parsed);
  await storage.write(current);
  emit();
  return current;
}

export function exportSettings() {
  return JSON.stringify(current, null, 2);
}

/** Lädt die aktuelle settings.json als Datei herunter. */
export function downloadSettings(filename = 'settings.json') {
  const blob = new Blob([exportSettings()], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

/* ---------------------------------------------------------------
   Einstellungen einer einzelnen Datenbank

   `databases` ist eine Liste, kein Objekt: So bleibt die Reihenfolge
   erhalten und die Datei lesbar, auch wenn Pfade Punkte enthalten — bei
   einem Objekt käme `get('databases.…')` mit seiner Pfadauflösung
   durcheinander.
   --------------------------------------------------------------- */

/** Die Einstellungen einer Datenbank, ergänzt um die Vorgabewerte. */
export function forDatabase(path) {
  const defaults = getSettings().databaseDefaults ?? {};
  const found = (getSettings().databases ?? []).find(d => d.path === path);
  return { ...structuredClone(defaults), ...(found ?? {}) };
}

/** Setzt einen Wert für genau eine Datenbank. */
export async function setForDatabase(path, key, value, options = {}) {
  if (!path) return;

  const list = [...(getSettings().databases ?? [])];
  const at = list.findIndex(d => d.path === path);

  if (at === -1) list.push({ path, [key]: value });
  else list[at] = { ...list[at], [key]: value };

  await set('databases', list, options);
}

/** Wirft die Einstellungen einer Datenbank weg. */
export function onSettingsChange(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

function emit() {
  for (const fn of listeners) fn(current);
}
