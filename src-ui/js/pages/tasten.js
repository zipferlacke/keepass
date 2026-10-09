/**
 * tasten.js — die Liste mit der Tastatur bedienen.
 *
 *   Strg+N            neuer Eintrag, aus jeder Ansicht
 *   Strg+F            zu den Einträgen und ins Suchfeld, aus jeder Ansicht
 *   einfach tippen    sucht — in den Einträgen auch ohne Klick ins Suchfeld
 *   ↑ ↓               durch Ordner und Einträge gehen
 *   Enter             Eintrag öffnen · Ordner auf- oder zuklappen
 *   Umschalt+Enter    Ordner samt allen Unterordnern auf- oder zuklappen
 *   Entf              Eintrag löschen (mit Rückfrage)
 *   Strg+X / Strg+V   Eintrag ausschneiden / in den Ordner der Zeile einfügen
 *   Esc               Ausgeschnittenes verwerfen, sonst die Suche leeren
 *
 * Ist ein Dialog oder ein Menü offen, die Datenbank gesperrt oder steht die
 * Schreibmarke in einem anderen Feld, bleibt alles beim Gewohnten — dort
 * gehören die Tasten dem Feld.
 *
 * Auf welcher Zeile die Tastatur steht, merkt sich das Modul am Inhalt
 * (Ordnerpfad, Kennung), nicht am Element: Die Tabelle wird bei jedem
 * Sortieren und Aufklappen neu gebaut.
 */

import { state, $ } from '../core/state.js';
import { byId } from '../core/entries.js';
import { showView } from '../core/navigation.js';
import * as pick from '../ui/multiselect.js';
import { startCreation } from '../dialogs/create.js';
import { openEntryDialog } from '../dialogs/entry.js';
import { runRowAction, cutEntries, clearCut, pasteInto } from './entries.js';

const ZEILEN = 'tr.tv-group-row, tr[data-id], tr[data-file-entry]';

/** Woran eine Zeile wiederzuerkennen ist, auch nach dem Neuzeichnen. */
const istOrdner = tr => tr.classList.contains('tv-group-row');

function kennung(tr) {
  if (istOrdner(tr)) return `g:${tr.dataset.groupPath}`;
  if (tr.dataset.id) return `e:${tr.dataset.id}`;
  return `f:${tr.dataset.fileEntry}/${tr.dataset.fileName}`;
}

let aktuell = null;

/** Alle Zeilen, die gerade zu sehen sind, in der Reihenfolge der Anzeige. */
function sichtbare() {
  return [...$('#entry-table').querySelectorAll(ZEILEN)].filter(tr => tr.getClientRects().length);
}

function zeile() {
  return aktuell ? sichtbare().find(tr => kennung(tr) === aktuell) ?? null : null;
}

/** Setzt die Markierung neu — nach jedem Neuzeichnen der Tabelle. */
function markiere(rollen = false) {
  const host = $('#entry-table');
  host.querySelectorAll('tr[data-current]').forEach(tr => tr.removeAttribute('data-current'));
  const tr = zeile();
  if (!tr) return;
  tr.setAttribute('data-current', '');
  if (rollen) tr.scrollIntoView({ block: 'nearest' });
}

function bewege(schritt) {
  const alle = sichtbare();
  if (!alle.length) return;
  const jetzt = alle.findIndex(tr => kennung(tr) === aktuell);
  const ziel = jetzt < 0
    ? (schritt > 0 ? 0 : alle.length - 1)
    : Math.min(alle.length - 1, Math.max(0, jetzt + schritt));
  aktuell = kennung(alle[ziel]);
  markiere(true);
}

/** Enter: Eintrag oder Datei öffnen, Ordner umklappen (mit Umschalt samt Unterbau). */
function oeffne(tr, samtUnterbau) {
  if (istOrdner(tr)) {
    // tableview klappt beim Klick auf die Gruppenzeile um — mit
    // Umschalttaste den ganzen Zweig. Genau das wird hier ausgelöst.
    tr.querySelector('.tv-group-content')
      ?.dispatchEvent(new MouseEvent('click', { bubbles: true, shiftKey: samtUnterbau }));
  } else if (tr.dataset.id) {
    openEntryDialog(tr.dataset.id);
  } else {
    tr.querySelector('td[data-col=name]')?.click();
  }
}

/** In welchen Ordner „Einfügen" auf dieser Zeile legt. */
function ordnerVon(tr) {
  if (!tr) return '';
  if (tr.dataset.folder) return tr.dataset.folder;
  return byId(tr.dataset.id ?? tr.dataset.fileEntry)?.folder ?? '';
}

function zurSuche() {
  if (state.view !== 'passwords' || state.kindFilter) {
    state.kindFilter = null;
    showView('passwords');
  }
  const feld = $('#search');
  feld.focus();
  feld.select();
}

function taste(ev) {
  if (state.locked || document.body.dataset.settingsOnly) return;
  // Meldungen oben im Fenster sind auch ein <dialog> — die zählen nicht.
  if (document.querySelector('dialog[open]:not(#notification_wrapper), .context-menu')) return;

  const strg = (ev.ctrlKey || ev.metaKey) && !ev.altKey;
  const buchstabe = ev.key.length === 1 ? ev.key.toLowerCase() : '';

  if (strg && buchstabe === 'n') { ev.preventDefault(); startCreation(); return; }
  if (strg && buchstabe === 'f') { ev.preventDefault(); zurSuche(); return; }

  if (state.view !== 'passwords') return;

  const suche = $('#search');
  const inSuche = ev.target === suche;
  // In einem anderen Feld gehören die Tasten dem Feld.
  if (!inSuche && ev.target.closest?.('input, textarea, select, [contenteditable]')) return;

  const tr = zeile();

  switch (ev.key) {
    case 'ArrowDown':
    case 'ArrowUp':
      ev.preventDefault();
      // Raus aus dem Suchfeld: Danach meinen Entf und Strg+X die Zeile,
      // nicht mehr den Text.
      if (inSuche) $('#entry-table').focus({ preventScroll: true });
      bewege(ev.key === 'ArrowDown' ? 1 : -1);
      return;

    case 'Enter':
      if (!tr) return;
      ev.preventDefault();
      oeffne(tr, ev.shiftKey);
      return;

    case 'Delete':
      if (inSuche || !tr?.dataset.id) return;
      ev.preventDefault();
      runRowAction('delete', tr.dataset.id);
      return;

    case 'Escape':
      if (clearCut()) return;
      if (suche.value) {
        suche.value = '';
        suche.dispatchEvent(new Event('input', { bubbles: true }));
      }
      return;
  }

  if (strg && buchstabe === 'x' && !inSuche) {
    const id = tr?.dataset.id;
    const ids = pick.selectionActive() ? pick.selectedIds() : (id ? [id] : []);
    if (!ids.length) return;
    ev.preventDefault();
    cutEntries(ids);
    return;
  }

  if (strg && buchstabe === 'v' && !inSuche && state.cut.length) {
    ev.preventDefault();
    pasteInto(ordnerVon(tr));
    return;
  }

  // Einfach lostippen: Das Zeichen landet im Suchfeld, weil der Fokus
  // dorthin wandert, bevor der Browser es einsetzt.
  if (!inSuche && !strg && !ev.altKey && ev.key.length === 1 && ev.key !== ' ') suche.focus();
}

export function bindTasten() {
  const host = $('#entry-table');
  // Damit die Liste den Fokus halten kann, wenn man mit den Pfeilen aus
  // dem Suchfeld kommt.
  host.tabIndex = -1;

  document.addEventListener('keydown', taste);

  // Ein Klick auf eine Zeile setzt die Tastatur dorthin.
  host.addEventListener('click', ev => {
    const tr = ev.target.closest(ZEILEN);
    if (!tr || !host.contains(tr)) return;
    aktuell = kennung(tr);
    markiere();
  });

  // Die Tabelle wird oft neu gebaut — die Markierung zieht mit.
  let geplant = false;
  new MutationObserver(() => {
    if (geplant) return;
    geplant = true;
    requestAnimationFrame(() => { geplant = false; markiere(); });
  }).observe(host, { childList: true, subtree: true });
}
