/**
 * formular.js — die Handgriffe, die jedes Formular im Dialog braucht.
 *
 * `userDialog` liefert die Werte am Ende als Objekt. Was dort steht,
 * hängt am `name` des Feldes — und weil die Bibliothek alles typisiert,
 * was wie eine Zahl aussieht, kommt aus einer PIN „1234" die Zahl 1234.
 * `captureFields` greift die Werte deshalb schon beim Tippen ab und
 * reicht sie unverändert weiter.
 *
 * Dazu das Passwortfeld mit Auge zum Aufdecken, wie es in allen Dialogen
 * vorkommt, und der Hinweis zur Güte einer PIN.
 */

import { esc, state } from '../core/state.js';

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
 * Für PINs ist das doppelt schädlich. `"1234"` kommt als `1234` an — wer
 * eine Zeichenkette erwartet, steht mit leeren Händen da und bricht stumm
 * ab. Und `"0123"` wird zu `123`: Die führende Null wäre still verloren,
 * und zwar nur auf diesem Weg. Der Willkommensablauf liest direkt am
 * Element ab und behielte sie — dieselbe PIN, zwei Ergebnisse.
 *
 * Deshalb lesen wir die Werte am Element statt aus den Daten des Dialogs.
 * Die Elemente behalten ihren Wert auch, nachdem der Dialog aus dem
 * Dokument entfernt wurde.
 *
 * Die Rückgabe passt in die Optionen von `dialog()`: `onInsert` dort
 * einsetzen, `value(name)` nach dem Abschicken lesen. Augen-Knöpfe werden
 * gleich mit verkabelt.
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
      // Erst die Augen-Knöpfe, dann einsammeln — und in dieser Reihenfolge
      // gekapselt, damit ein Fehler im einen nicht das andere verhindert.
      try { wirePasswordFields(); } catch { /* Auge fehlt, weiter */ }
      collect();
    }),

    /**
     * Der Wert des Feldes.
     *
     * `data` ist der Rückfallweg: Kam der Dialog nie durch `onInsert` —
     * etwa weil ein Aufrufer es zu setzen vergisst —, wird der Wert doch
     * noch aus den Daten des Dialogs gelesen. Zahlen werden dabei
     * zurückverwandelt. Eine führende Null ist dann verloren; besser als
     * wortlos gar nichts zu liefern.
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

/** Häkchen aus einem Dialog — kommt mal als `true`, mal als `"on"`. */
export function fieldChecked(data, name) {
  const value = data?.[name];
  return value === true || value === 'on' || value === 'true';
}

/** Erklärt in einem Satz, wie stark die PIN auf diesem Gerät ist. */
export function pinStrengthNote() {
  return state.unlock.keyring
    ? `Der Schlüssel entsteht aus deiner PIN <em>und</em> einem Zufallswert im
       Schlüsselbund des Systems. Ein Angreifer bräuchte beides: die PIN und
       deine angemeldete Sitzung.`
    : `<strong>Auf diesem Gerät ist kein Schlüsselbund erreichbar.</strong>
       Dann hängt alles allein an der PIN — wähle sie entsprechend lang.`;
}

/**
 * Baut ein Passwortfeld mit Auge zum Sichtbarmachen.
 *
 * `userDialog` liefert die Werte über `name`, deshalb muss der Umschalter
 * am `type` drehen und darf das Feld nicht ersetzen.
 */
export function passwordField(name, placeholder, { required = true, minlength = 0 } = {}) {
  return `<span class="pw-field">
    <input type="password" name="${name}" placeholder="${placeholder}" autocomplete="new-password"
           ${required ? 'required' : ''} ${minlength ? `minlength="${minlength}"` : ''}>
    <button type="button" class="pw-eye" data-shape="square no-background"
            title="Sichtbar machen" aria-label="Sichtbar machen"><span class="msr">visibility</span></button>
  </span>`;
}

/** Hängt die Augen-Knöpfe an, sobald der Dialog im DOM steht. */
export function wirePasswordFields(root = document) {
  root.querySelectorAll?.('.pw-eye').forEach(btn => {
    if (btn.dataset.wired) return;
    btn.dataset.wired = '1';

    btn.addEventListener('click', () => {
      const field = btn.previousElementSibling;
      const shown = field.type === 'text';
      field.type = shown ? 'password' : 'text';
      btn.querySelector('.msr').textContent = shown ? 'visibility' : 'visibility_off';
      btn.title = btn.ariaLabel = shown ? 'Sichtbar machen' : 'Verbergen';
      field.focus();
    });
  });
}
