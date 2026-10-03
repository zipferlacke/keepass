/**
 * multiselect.js — mehrere Einträge auswählen und gemeinsam bewegen.
 *
 * Wie die Auswahl beginnt:
 *
 *   Strg-Klick      wählt einzeln
 *   Umschalt-Klick  den Bereich zwischen zuletzt gewähltem und geklicktem
 *   langes Drücken  auf jedem Gerät, auch mit der Maus
 *
 * Sobald etwas ausgewählt ist, erscheinen links Kästchen, und ein
 * gewöhnlicher Klick schaltet um statt zu öffnen. So kommt man ohne
 * getrennten „Auswahlmodus" aus.
 *
 * # Nur innerhalb eines Ordners
 *
 * Eine Auswahl gilt immer für genau einen Ordner. Wer in einem anderen
 * anfängt, beginnt eine neue — alles andere führt zu Auswahlen, die man
 * nirgends mehr im Zusammenhang sieht, und zu Verschiebungen, die halb
 * gelingen. Der Bereich bei Umschalt-Klick richtet sich nach der
 * **angezeigten** Reihenfolge, damit er nach dem Sortieren stimmt.
 */

const LONG_PRESS_MS = 450;
const MOVE_TOLERANCE = 10;

const selected = new Set();
let folder = null;          // Ordner, für den die Auswahl gilt
let anchor = null;          // Ausgangspunkt für Umschalt-Klick
let onChange = () => {};

export function selectedIds() {
  return [...selected];
}

export const isSelected = id => selected.has(id);
export const selectionActive = () => selected.size > 0;

export function clearSelection() {
  if (!selected.size) return;
  selected.clear();
  folder = null;
  anchor = null;
  onChange();
}

/** Wird gerufen, wenn sich die Auswahl ändert — die Oberfläche zeichnet neu. */
export function onSelectionChange(fn) {
  onChange = fn;
}

/**
 * Hängt die Auswahl an eine frisch gebaute Liste.
 *
 * @param {Element} root      Behälter mit den Zeilen
 * @param {(id: string) => string} folderOf  Ordner eines Eintrags
 */
export function wireSelection(root, folderOf) {
  const rows = [...root.querySelectorAll('[data-id]')];
  const order = () => rows.map(r => r.dataset.id);

  for (const row of rows) {
    const id = row.dataset.id;
    row.toggleAttribute('data-selected', selected.has(id));

    row.addEventListener('click', ev => {
      if (ev.ctrlKey || ev.metaKey) {
        stop(ev);
        toggle(id, folderOf(id));
      } else if (ev.shiftKey && anchor) {
        stop(ev);
        selectRange(anchor, id, order(), folderOf);
      } else if (selected.size) {
        stop(ev);
        toggle(id, folderOf(id));
      }
    }, true);

    bindLongPress(row, () => {
      if (!selected.size) toggle(id, folderOf(id));
    });
  }
}

function stop(ev) {
  ev.preventDefault();
  ev.stopPropagation();
}

/**
 * Langes Drücken — auf allen Zeigergeräten, auch mit der Maus.
 *
 * Wandert der Zeiger, wird abgebrochen: Sonst löste jedes Ziehen und jedes
 * Scrollen mit dem Finger eine Auswahl aus.
 */
function bindLongPress(element, action) {
  let timer = null;
  let start = null;

  const cancel = () => { clearTimeout(timer); timer = null; start = null; };

  element.addEventListener('pointerdown', ev => {
    // Nur die Haupttaste; mit der rechten kommt das Kontextmenü.
    if (ev.button !== 0) return;

    start = { x: ev.clientX, y: ev.clientY };
    timer = setTimeout(() => {
      timer = null;
      action();
      navigator.vibrate?.(20);
    }, LONG_PRESS_MS);
  });

  element.addEventListener('pointermove', ev => {
    if (!start) return;
    if (Math.hypot(ev.clientX - start.x, ev.clientY - start.y) > MOVE_TOLERANCE) cancel();
  });

  for (const name of ['pointerup', 'pointercancel', 'pointerleave']) {
    element.addEventListener(name, cancel);
  }

  // Nach langem Drücken darf der folgende Klick nicht auch noch wirken.
  element.addEventListener('click', ev => {
    if (start === null && timer === null) return;
    stop(ev);
  }, true);
}

function toggle(id, home) {
  // Anderer Ordner: Das ist eine neue Auswahl, keine Erweiterung.
  if (selected.size && home !== folder) {
    selected.clear();
    anchor = null;
  }
  folder = home;

  if (selected.has(id)) selected.delete(id);
  else { selected.add(id); anchor = id; }

  if (!selected.size) { folder = null; anchor = null; }
  onChange();
}

function selectRange(from, to, order, folderOf) {
  const a = order.indexOf(from);
  const b = order.indexOf(to);
  if (a === -1 || b === -1) return;

  for (const id of order.slice(Math.min(a, b), Math.max(a, b) + 1)) {
    // Der Bereich kann über Ordnergrenzen laufen — dann nur der eigene.
    if (folderOf(id) === folder) selected.add(id);
  }
  onChange();
}
