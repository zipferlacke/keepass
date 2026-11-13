/**
 * navigation.js — welche Ansicht gerade zu sehen ist.
 *
 * Vier Ansichten liegen übereinander im selben Dokument; sichtbar ist
 * die mit `data-active`. Hier wird umgeschaltet, der Titel gesetzt und
 * genau die eine Seite gezeichnet, die man jetzt sieht.
 *
 * Bei gesperrter Datenbank sind nur die Einstellungen erreichbar
 * (Zahnrad am Sperrbildschirm).
 */

import { state, $, $$, viewTitle } from './state.js';
import { t } from './i18n.js';
import { zeichne } from './render.js';

/* =========================================================
   Navigation
   ========================================================= */
export function showView(name) {
  // Gesperrt ist nur die Ansicht „Einstellungen" verfügbar.
  if (state.locked && !document.body.dataset.settingsOnly) return;
  state.view = name;

  $$('.view').forEach(v => v.toggleAttribute('data-active', v.id === `view-${name}`));

  $$('.app-nav button[data-view]').forEach(b => {
    if (b.classList.contains('brand')) return;
    if (b.dataset.view === name) b.setAttribute('aria-current', 'page');
    else b.removeAttribute('aria-current');
  });

  // Suche und Tag-Leiste gehören zum Abschnitt der Passwortliste und sind
  // in anderen Ansichten ausgeblendet.
  const isPasswords = name === 'passwords';

  $('#btn-add').hidden = name === 'settings' || name === 'security';

  $('#app-title').textContent = isPasswords && state.kindFilter === 'files'
    ? t('navigation.titel.dateien') : viewTitle(name);

  // Nur die Seite zeichnen, die man gerade ansieht.
  if (isPasswords) { zeichne('schlagworte'); zeichne('einträge'); }
  if (name === 'security') zeichne('sicherheit');
  if (name === 'settings') zeichne('einstellungen');
  if (name === 'totp') zeichne('totp');
}
