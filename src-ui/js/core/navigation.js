/**
 * navigation.js — welche Ansicht gerade zu sehen ist.
 *
 * Vier Ansichten liegen übereinander im selben Dokument; sichtbar ist
 * die mit `data-active`. Hier wird umgeschaltet, der Titel gesetzt und
 * genau die eine Seite gezeichnet, die man jetzt sieht.
 *
 * Bei gesperrter Datenbank geht gar nichts — außer den Einstellungen,
 * die über das Zahnrad am Sperrbildschirm erreichbar sind.
 */

import { state, $, $$, VIEW_TITLES } from './state.js';
import { zeichne } from './render.js';

/* =========================================================
   Navigation
   ========================================================= */
export function showView(name) {
  // Bei gesperrter Datenbank gibt es nur eine sinnvolle Ansicht: die
  // Einstellungen, aufgerufen über das Zahnrad am Sperrbildschirm.
  if (state.locked && !document.body.dataset.settingsOnly) return;
  state.view = name;

  $$('.view').forEach(v => v.toggleAttribute('data-active', v.id === `view-${name}`));

  $$('.app-nav button[data-view]').forEach(b => {
    if (b.classList.contains('brand')) return;
    if (b.dataset.view === name) b.setAttribute('aria-current', 'page');
    else b.removeAttribute('aria-current');
  });

  // Suche und Tag-Leiste stecken im Abschnitt der Passwortliste und
  // verschwinden dadurch von selbst, sobald eine andere Ansicht aktiv ist.
  const isPasswords = name === 'passwords';

  $('#btn-add').hidden = name === 'settings' || name === 'security';

  $('#app-title').textContent = isPasswords && state.kindFilter === 'files'
    ? 'Dateien' : (VIEW_TITLES[name] ?? 'WKeePass');

  // Nur die Seite zeichnen, die man gerade ansieht.
  if (isPasswords) { zeichne('schlagworte'); zeichne('einträge'); }
  if (name === 'security') zeichne('sicherheit');
  if (name === 'settings') zeichne('einstellungen');
  if (name === 'totp') zeichne('totp');
}
