/**
 * libs.js — einzige Anbindung an wuefl-libs.
 *
 * Lädt userDialog, banner, tableview und qrcode. Es gibt keine
 * Ersatzimplementierungen; ist die Bibliothek nicht erreichbar, ist das ein Fehler.
 *
 * Die Bibliothek liegt lokal im Programm. So funktionieren Dialoge ohne
 * Netzverbindung, und kein fremder Server liefert Code neben die Passwörter.
 *
 * `libs/wuefl-libs-v2-2-1` ist ein Symlink auf das Schwesterprojekt, dem
 * Tauri beim Bauen folgt (`follow_links(true)`). Die Version steht im Namen
 * und in der `@import`-Zeile am Anfang von `css/app.css`.
 */

import { t } from '../core/i18n.js';

const BASE = '../../libs/wuefl-libs-v2-2-1';

const modules = new Map();

/** Lädt ein Modul aus wuefl-libs genau einmal. */
function load(path) {
  if (!modules.has(path)) modules.set(path, import(`${BASE}/${path}`));
  return modules.get(path);
}

/**
 * Lädt den SelectPicker aus wuefl-libs.
 *
 * Danach übernimmt er jedes `<select data-sp-picker>`, auch später
 * hinzugefügte (er beobachtet das Dokument). Ohne ihn zeichnet das
 * Betriebssystem die Liste.
 */
export function selectPicker() {
  return load('selectpicker/selectpicker.js');
}

/* =========================================================
   Dialoge und Meldungen
   ========================================================= */

/**
 * userDialog(o) → Promise<{ submit, data }>
 *
 * „Abbrechen" steht entweder unten in der Leiste oder oben rechts als „×",
 * nie beides (Verhalten der Bibliothek seit 2.7.0).
 */
export async function dialog(options) {
  const { userDialog } = await load('userDialog/userDialog.js');
  // Standardlage: am Handy unten, am Rechner rechts (überschreibbar über `position`).
  // „Abbrechen" und „Zurück" werden in der gewählten Sprache beschriftet;
  // der Zurück-Pfeil entsteht durch `onBack`.
  const zurueck = options.onBack && !options.barLeft
    ? { barLeft: { icon: '<span class="msr">arrow_back</span>', title: t('allgemein.knoepfe.zurueck'), onClick: options.onBack } }
    : {};
  return userDialog({ position: { small: 'bottom', wide: 'right' }, cancelText: t('allgemein.knoepfe.abbrechen'), ...zurueck, ...options });
}

/** showBanner(content, type, duration) */
export async function banner(content, type = 'info', duration = 3500) {
  const { showBanner } = await load('banner/banner.js');
  return showBanner(content, type, duration);
}

/**
 * Schließt den Dialog, in dem ein Element steckt, über dessen eigene Knöpfe.
 * `userDialog` löst sein Promise nur beim Klick auf `.dialog_close` oder
 * beim Absenden des Formulars auf; ein direktes `dialog.close()` würde es
 * offen lassen.
 *
 * Ohne Fußzeile wird das „×" oben in der Leiste verwendet, sonst `uDFinish`
 * aus der Bibliothek. Übernehmen und Abbrechen sind dann gleichwertig; das
 * Ergebnis (Auswahl, erkannter Code) hat der Aufrufer bereits festgehalten.
 */
export function closeHostDialog(element, ok = true) {
  const host = element?.closest('dialog');
  if (!host) return false;

  const submit = host.querySelector('.dialog_submit');
  const cancel = host.querySelector('.dialog_close');
  if (submit || cancel) {
    (ok ? (submit ?? cancel) : (cancel ?? submit)).click();
    return true;
  }

  const bar = host.querySelector('.uD-bar-right');
  if (bar) { bar.click(); return true; }
  if (typeof host.uDFinish === 'function') { host.uDFinish('cancel'); return true; }
  return false;
}

/* =========================================================
   Tabellen
   ========================================================= */

/**
 * Rüstet Tabellen mit Sortierung aus.
 *
 * tableview liest `td.dataset.sortValue`; im HTML heißt das Attribut
 * `data-sort-value`.
 */
export function tableview() {
  return load('tableview/tableview.js').then(tv => {
    // Pfeile und Symbole kommen aus der Symbolschrift statt aus UTF-8-
    // Zeichen, die Browser unterschiedlich darstellen.
    if (!iconsSet) { iconsSet = true; tv.setIcons('msr'); }
    return tv;
  });
}
let iconsSet = false;

/* =========================================================
   QR-Codes zeichnen
   ========================================================= */

export async function renderQrCode(element, colors = {}) {
  const { default: QRCodes } = await load('qrcode/qrcode-min.js');

  QRCodes([element], undefined, 'qrcode', {
    dots: colors.dots ?? '#18181b',
    cornersSquare: colors.corners ?? '#18181b',
    cornersDot: colors.corners ?? '#18181b',
    background: colors.background ?? '#ffffff'
  });
}

/**
 * Oben links „Zurück": schließt den Dialog und öffnet den vorherigen. Ohne
 * Ziel gibt es keinen Pfeil.
 *
 * Eine kurze Pause stellt sicher, dass der alte Dialog aus dem Dokument
 * entfernt ist, bevor der neue erscheint.
 */
export function zurueckZu(ziel) {
  if (typeof ziel !== 'function') return null;
  return dlg => {
    closeHostDialog(dlg, false);
    setTimeout(() => ziel(), 50);
  };
}
