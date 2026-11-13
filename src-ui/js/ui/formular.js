/**
 * formular.js — die Handgriffe, die jedes Formular im Dialog braucht.
 *
 * `userDialog` liefert die Werte als Objekt nach dem `name` des Feldes und
 * wandelt dabei zahlenähnliche Werte in Zahlen um (aus der PIN „1234" wird
 * 1234). `captureFields` liest die Werte deshalb unverändert am Element ab.
 *
 * Außerdem enthalten: das Passwortfeld mit Auge zum Aufdecken und der
 * Hinweis zur Stärke einer PIN.
 */

import { esc, state } from '../core/state.js';
import { aufdeckbar } from './aufdecken.js';
import { t } from '../core/i18n.js';

/**
 * Liest Textfelder eines Dialogs unverfälscht ab.
 *
 * `userDialog` wandelt jeden Wert, der wie eine Zahl aussieht, in eine Zahl
 * um, bevor es ihn zurückgibt:
 *
 * ```js
 * if (v !== "" && !isNaN(v)) return true;   // Zahlen sind okay
 * allValues = allConvertible ? rawValues.map(v => Number(v)) : rawValues;
 * ```
 *
 * Für PINs ist das ungeeignet: „1234" käme als Zahl an, und bei „0123" ginge
 * die führende Null verloren. Die Werte werden daher am Element gelesen;
 * die Elemente behalten ihren Wert auch nach dem Entfernen des Dialogs.
 *
 * Die Rückgabe passt in die Optionen von `dialog()`: `onInsert` dort
 * einsetzen, `value(name)` nach dem Abschicken lesen. Augen-Knöpfe werden
 * mit angebunden.
 */
export function captureFields(...names) {
  const fields = new Map();

  const collect = () => {
    const host = document.querySelector('dialog[open]') ?? document;
    for (const name of names) {
      const field = host.querySelector(`[name="${name}"]`);
      if (field) fields.set(name, field);
    }
  };

  return {
    onInsert: () => queueMicrotask(() => {
      // Augen-Knöpfe anbinden und Felder einsammeln; getrennt abgesichert,
      // damit ein Fehler das jeweils andere nicht verhindert.
      try { wirePasswordFields(); } catch { /* ohne Auge-Knopf */ }
      collect();
    }),

    /**
     * Der Wert des Feldes. `data` ist der Rückfall, wenn `onInsert` nicht
     * gesetzt wurde: Der Wert kommt dann aus den Daten des Dialogs, Zahlen
     * werden zurück in Text verwandelt, eine führende Null geht verloren.
     */
    value: (name, data = null) => {
      const field = fields.get(name);
      if (field) return String(field.value ?? '').trim();

      const raw = data?.[name];
      if (raw === undefined || raw === null) return '';
      return String(Array.isArray(raw) ? raw[0] ?? '' : raw).trim();
    }
  };
}

/**
 * Setzt den Fokus ins genannte Feld des offenen Dialogs. Der Dialog fokussiert
 * beim Öffnen selbst das erste bedienbare Element; deshalb erfolgt der Aufruf
 * zwei Bildaufbauten später.
 */
export function fokusInsFeld(name) {
  requestAnimationFrame(() => requestAnimationFrame(() => {
    document.querySelector(`dialog[open] [name="${name}"]`)?.focus();
  }));
}

/** Häkchen aus einem Dialog; der Wert kommt als `true` oder `"on"`. */
export function fieldChecked(data, name) {
  const value = data?.[name];
  return value === true || value === 'on' || value === 'true';
}

/** Erklärt in einem Satz, wie stark die PIN auf diesem Gerät ist. */
export function pinStrengthNote() {
  return state.unlock.keyring
    ? t('ui.formular.pinMitSchluesselbund')
    : t('ui.formular.pinOhneSchluesselbund');
}

/**
 * Baut ein Passwortfeld mit Auge zum Sichtbarmachen.
 *
 * `userDialog` liefert die Werte über `name` — das Passwortfeld bleibt
 * deshalb, wo es ist; aufgedeckt steht sein Zwilling davor (aufdecken.js).
 */
export function passwordField(name, placeholder, { required = true, minlength = 0 } = {}) {
  return `<span class="pw-field">
    <input type="password" name="${name}" placeholder="${placeholder}" autocomplete="new-password"
           ${required ? 'required' : ''} ${minlength ? `minlength="${minlength}"` : ''}>
    <button type="button" class="pw-eye" data-shape="square no-background"
            title="${t('ui.formular.sichtbarMachen')}" aria-label="${t('ui.formular.sichtbarMachen')}"><span class="msr">visibility</span></button>
  </span>`;
}

/** Hängt die Augen-Knöpfe an, sobald der Dialog im DOM steht. */
export function wirePasswordFields(root = document) {
  root.querySelectorAll?.('.pw-eye').forEach(btn => {
    if (btn.dataset.wired) return;
    btn.dataset.wired = '1';

    // Aufgedeckt ist das Feld ein echtes Textfeld (siehe aufdecken.js).
    const feld = aufdeckbar(btn.parentElement.querySelector('input'));

    btn.addEventListener('click', () => {
      const shown = feld.sichtbar;
      feld.zeigen(!shown);
      btn.querySelector('.msr').textContent = shown ? 'visibility' : 'visibility_off';
      btn.title = btn.ariaLabel = shown ? t('ui.formular.sichtbarMachen') : t('ui.formular.verbergen');
      feld.aktiv.focus();
    });
  });
}
