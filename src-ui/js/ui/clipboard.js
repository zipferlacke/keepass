/**
 * clipboard.js — kopieren, und danach wieder aufräumen.
 *
 * Der kopierte Inhalt wird nach einer Frist aus der Zwischenablage gelöscht,
 * da andere Anwendungen sie lesen können. Die Frist steht in den
 * Einstellungen; `0` löscht nie.
 *
 * Geheimnisse kopiert `vault.copySecret`, ohne den Wert durch die
 * Oberfläche zu leiten. Dieses Modul kopiert nur offen sichtbare Werte:
 * Benutzername, Adresse, Notiz.
 */

import * as settings from '../data/settings.js';
import { banner } from './libs.js';
import { t } from '../core/i18n.js';

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
    banner(t('ui.zwischenablage.fehler'), 'error');
    return false;
  }
}
