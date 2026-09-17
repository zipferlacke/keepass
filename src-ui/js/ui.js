/**
 * ui.js — die einzige Stelle, die wuefl-libs kennt.
 *
 * Alle vier genutzten Bausteine werden hier geladen: userDialog, banner,
 * tableview und qrcode. Es gibt keine Ersatzimplementierungen — ist die
 * Bibliothek nicht erreichbar, ist das ein Fehler und soll auch als
 * solcher auffallen.
 *
 * Die Bibliothek liegt **lokal** im Programm, nicht auf einem Server. Für
 * einen Passwortmanager ist das keine Kleinigkeit: Käme sie aus dem Netz,
 * gäbe es ohne Verbindung keinen einzigen Dialog — und wer den Server hat,
 * führte Code neben deinen Passwörtern aus.
 *
 * `libs/wuefl-libs-v2-2-1` ist ein Symlink auf das Schwesterprojekt. Beim
 * Bauen folgt Tauri ihm (`follow_links(true)`), die Dateien landen also im
 * Programm. Die Fassung steht im Namen — beim Aktualisieren wird der Link
 * neu gesetzt und diese Zeile mit, dann fällt ein vergessener Pfad sofort
 * auf, statt still die alte Fassung zu laden.
 *
 * Wird umgestellt, muss die `@import`-Zeile ganz oben in `css/app.css` mit.
 */

const BASE = '../libs/wuefl-libs-v2-2-1';

const modules = new Map();

/** Lädt ein Modul aus wuefl-libs genau einmal. */
function load(path) {
  if (!modules.has(path)) modules.set(path, import(`${BASE}/${path}`));
  return modules.get(path);
}

/**
 * Lädt den SelectPicker aus wuefl-libs.
 *
 * Danach übernimmt er von selbst jedes `<select data-sp-picker>` — auch
 * solche, die später dazukommen; er hört auf Änderungen am Dokument. Ohne
 * ihn zeichnet das Betriebssystem die Liste, und auf dem Handy sieht das
 * neben dem Rest der Oberfläche fremd aus.
 */
export function selectPicker() {
  return load('selectpicker/selectpicker.js');
}

/* =========================================================
   Dialoge und Meldungen
   ========================================================= */

/** userDialog(o) → Promise<{ submit, data }> */
export async function dialog(options) {
  const { userDialog } = await load('userDialog/userDialog.js');
  return userDialog(options);
}

/** showBanner(content, type, duration) */
export async function banner(content, type = 'info', duration = 3500) {
  const { showBanner } = await load('banner/banner.js');
  return showBanner(content, type, duration);
}

/**
 * Schließt den Dialog, in dem ein Element steckt — über dessen eigene
 * Knöpfe. Wichtig: userDialog löst sein Promise ausschließlich beim Klick
 * auf `.dialog_close` oder beim Absenden des Formulars auf. Ein direktes
 * `dialog.close()` lässt den Aufrufer hängen.
 */
export function closeHostDialog(element, ok = true) {
  const host = element?.closest('dialog');
  if (!host) return false;

  const submit = host.querySelector('.dialog_submit');
  const cancel = host.querySelector('.dialog_close');
  if (!submit && !cancel) return false;

  (ok ? (submit ?? cancel) : (cancel ?? submit)).click();
  return true;
}

/* =========================================================
   Tabellen
   ========================================================= */

/**
 * Rüstet Tabellen mit Sortierung aus.
 *
 * Achtung: tableview liest `td.dataset.sortValue` — im HTML muss das
 * Attribut deshalb `data-sort-value` heißen, nicht `data-sortValue`.
 */
export function tableview() {
  return load('tableview/tableview.js');
}

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
