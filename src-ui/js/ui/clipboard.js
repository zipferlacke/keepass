/**
 * clipboard.js — kopieren, und danach wieder aufräumen.
 *
 * Alles, was in der Zwischenablage landet, verschwindet nach einer Weile
 * von selbst wieder: Ein Passwort, das dort liegen bleibt, liest jede
 * andere Anwendung mit. Wie lange, steht in den Einstellungen; `0` heißt
 * „gar nicht löschen".
 *
 * Für Geheimnisse gibt es `vault.copySecret` — der Wert wandert dort gar
 * nicht erst durch die Oberfläche. Hier geht nur, was ohnehin offen
 * dasteht: Benutzername, Adresse, Notiz.
 */

import * as settings from '../data/settings.js';
import { banner } from './libs.js';

let clipboardTimer = null;

export function scheduleClipboardClear() {
  const secs = settings.get('unlock.clipboardClearSeconds', 30);
  if (!secs) return;
  clearTimeout(clipboardTimer);
  clipboardTimer = setTimeout(() => navigator.clipboard.writeText('').catch(() => {}), secs * 1000);
}

export async function copyPlain(value, message) {
  try {
    await navigator.clipboard.writeText(value ?? '');
    banner(message, 'success', 1800);
    scheduleClipboardClear();
    return true;
  } catch {
    banner('Kopieren nicht möglich.', 'error');
    return false;
  }
}
