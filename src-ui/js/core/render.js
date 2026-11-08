/**
 * render.js — der Mittelpunkt des Zeichnens.
 *
 * Jede Seite meldet sich hier einmal an (`seite('einträge', renderPasswords)`)
 * und wird danach von `renderAll()` mitgezeichnet. So kennen die Seiten
 * diese Datei, aber diese Datei keine Seite.
 *
 * Gezeichnet wird in der Reihenfolge der Anmeldung (die Reihenfolge der
 * Einbindung in `app.js`). Einzelne Seiten lassen sich auslassen:
 * `renderAll({ ohne: ['einstellungen'] })`.
 *
 * `refreshFromVault()` holt die Einträge neu aus dem Kern. Was danach
 * einmal durchlaufen soll — etwa das Nachholen fehlender Titel —, wird mit
 * `nachLaden()` angemeldet.
 */

import * as vault from '../data/vault.js';
import * as settings from '../data/settings.js';
import { state } from './state.js';
import { banner } from '../ui/libs.js';
import { t } from './i18n.js';

const seiten = new Map();
const nachher = [];

/** Meldet eine Seite zum Zeichnen an. */
export function seite(name, fn) {
  seiten.set(name, fn);
}

/** Meldet etwas an, das nach jedem Laden aus dem Kern einmal läuft. */
export function nachLaden(fn) {
  nachher.push(fn);
}

let laeuft = false;

/**
 * Zeichnet alle angemeldeten Seiten.
 *
 * Gesperrt wird nichts gezeichnet — dann steht der Sperrbildschirm davor.
 * Eine Sperre gegen Wiedereintritt verhindert rekursives Zeichnen.
 */
export function renderAll({ ohne = [] } = {}) {
  if (laeuft || state.locked) return;
  laeuft = true;
  try {
    for (const [name, fn] of seiten) {
      if (!ohne.includes(name)) fn();
    }
  } finally {
    laeuft = false;
  }
}

/**
 * Zeichnet eine einzelne Seite neu, ohne die übrigen anzufassen.
 */
export function zeichne(name) {
  if (state.locked) return;
  seiten.get(name)?.();
}

/** Holt Einträge, Stärkewerte und Mehrfachnutzung neu aus dem Kern. */
export async function refreshFromVault() {
  state.entries = await vault.listEntries();
  state.strength = settings.get('checks.passwordStrength', true)
    ? await vault.strengthMap()
    : new Map();
  state.reused = settings.get('checks.reuseDetection', true)
    ? await vault.reusedIds()
    : new Set();
  for (const fn of nachher) queueMicrotask(fn);
}

let syncing = false;
let lastSyncError = '';

/** Holt, was ein anderes Gerät in die Datei geschrieben hat, und mischt es ein. */
export async function syncFromFile() {
  if (syncing) return;
  syncing = true;
  try {
    if (await vault.sync()) await takeForeign();
    lastSyncError = '';
  } catch (err) {
    // Dieselbe Fehlermeldung wird nur einmal angezeigt.
    const message = err?.message ?? String(err);
    if (message !== lastSyncError) banner(message, 'error', 10000);
    lastSyncError = message;
  } finally {
    syncing = false;
  }
}

/** Übernimmt einen fremden Stand, den der Kern schon eingemischt hat. */
export async function takeForeign() {
  if (state.locked) return;
  await refreshFromVault();
  renderAll({ ohne: ['einstellungen'] });
  banner(t('ui.abgleich.uebernommen'), 'success', 4000);
}

/**
 * Nach einer Änderung an der Ordnung — verschoben, umbenannt, gelöscht:
 * schreiben, neu laden, neu zeichnen, Meldung anzeigen. Die Einstellungen
 * werden nicht neu gezeichnet.
 */
export async function nachStrukturaenderung(meldung) {
  await vault.commit();
  await refreshFromVault();
  renderAll({ ohne: ['einstellungen'] });
  banner(meldung, 'success');
}
