/**
 * render.js — der Mittelpunkt des Zeichnens.
 *
 * Jede Seite meldet sich hier einmal an (`seite('einträge', renderPasswords)`)
 * und wird danach von `renderAll()` mitgezeichnet. Das spart den Ringschluss:
 * Die Seiten kennen diese Datei, diese Datei kennt keine Seite.
 *
 * Die Reihenfolge ist die der Anmeldung — also die, in der `app.js` die
 * Seiten einbindet. Wer eine Seite auslassen will, nennt ihren Namen:
 * `renderAll({ ohne: ['einstellungen'] })`.
 *
 * `refreshFromVault()` holt die Einträge neu aus dem Kern. Was danach
 * einmal durchlaufen soll — etwa das Nachholen fehlender Titel — meldet
 * sich mit `nachLaden()` an.
 */

import * as vault from '../data/vault.js';
import * as settings from '../data/settings.js';
import { state } from './state.js';
import { banner } from '../ui/libs.js';

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
 * Die Sperre gegen Wiedereintritt verhindert, dass ein Zeichnen, das
 * selbst wieder etwas auslöst, sich im Kreis dreht.
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
 * Zeichnet eine einzelne Seite nach — für Stellen, die wissen, was sich
 * geändert hat, und nicht alles neu malen wollen.
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
    // Jede Minute dieselbe Meldung wäre nur lästig.
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
  banner('Änderungen von einem anderen Gerät übernommen.', 'success', 4000);
}

/**
 * Nach einer Änderung an der Ordnung — verschoben, umbenannt, gelöscht:
 * schreiben, neu laden, neu zeichnen, Bescheid sagen. Die Einstellungen
 * bleiben stehen, dort ändert sich dabei nichts.
 */
export async function nachStrukturaenderung(meldung) {
  await vault.commit();
  await refreshFromVault();
  renderAll({ ohne: ['einstellungen'] });
  banner(meldung, 'success');
}
