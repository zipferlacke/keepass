/**
 * aufdecken.js — ein Passwortfeld sichtbar machen, als echtes Textfeld.
 *
 * Den `type` von „password" auf „text" umzustellen genügt nicht: Der Browser
 * meldet der Bildschirmtastatur weiterhin ein Passwortfeld, sodass am Handy
 * Markieren, Kopieren und die Zwischenablage der Tastatur fehlen.
 *
 * Das Feld erhält daher einen Zwilling, der von Anfang an ein Textfeld ist.
 * Aufgedeckt ersetzt der Zwilling das Passwortfeld, verdeckt ist wieder das
 * Passwortfeld sichtbar. Beide führen denselben Wert.
 *
 * Das Passwortfeld behält `id` und `name`; Eingaben im Zwilling kommen dort
 * als gewöhnliches `input`-Ereignis an, und `feld.value = …` setzt beide.
 */

const WERT = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');

/** Was der Zwilling vom Passwortfeld übernimmt. */
const ERBT = ['placeholder', 'required', 'minlength', 'maxlength', 'class', 'aria-label', 'aria-describedby'];

/**
 * @param {HTMLInputElement} feld  das Passwortfeld
 * @returns {{ zeigen(an: boolean): void, readonly sichtbar: boolean, readonly aktiv: HTMLInputElement }}
 */
export function aufdeckbar(feld) {
  if (feld._aufdeckbar) return feld._aufdeckbar;

  const klar = document.createElement('input');
  klar.type = 'text';
  for (const name of ERBT) {
    if (feld.hasAttribute(name)) klar.setAttribute(name, feld.getAttribute(name));
  }
  // Geheimnis: keine Vorschläge, Korrekturen oder Merkfunktionen.
  klar.autocomplete = 'off';
  klar.autocapitalize = 'off';
  klar.spellcheck = false;
  klar.setAttribute('autocorrect', 'off');
  klar.dataset.klartext = '';
  klar.hidden = true;
  feld.after(klar);

  // Vom Zwilling zum Feld.
  for (const art of ['input', 'change']) {
    klar.addEventListener(art, () => {
      WERT.set.call(feld, klar.value);
      feld.dispatchEvent(new Event(art, { bubbles: true }));
    });
  }
  // Vom Feld zum Zwilling: getippt …
  feld.addEventListener('input', () => { if (klar.value !== feld.value) klar.value = feld.value; });
  // … und gesetzt (`feld.value = …` aus dem Programm).
  Object.defineProperty(feld, 'value', {
    configurable: true,
    get: () => WERT.get.call(feld),
    set: wert => { WERT.set.call(feld, wert); klar.value = WERT.get.call(feld); }
  });

  // Attribute des Feldes (Platzhalter, gesperrt, Tastaturart) auf den Zwilling übertragen.
  const MIT = ['placeholder', 'disabled', 'inputmode', 'required', 'minlength', 'maxlength'];
  new MutationObserver(aenderungen => {
    for (const { attributeName: name } of aenderungen) {
      if (feld.hasAttribute(name)) klar.setAttribute(name, feld.getAttribute(name));
      else klar.removeAttribute(name);
    }
  }).observe(feld, { attributes: true, attributeFilter: MIT });
  if (feld.hasAttribute('inputmode')) klar.setAttribute('inputmode', feld.getAttribute('inputmode'));
  if (feld.disabled) klar.disabled = true;

  // Fokus und Fehlermeldung gehen an das sichtbare Feld.
  for (const name of ['focus', 'select', 'setCustomValidity', 'reportValidity']) {
    const eigen = HTMLInputElement.prototype[name];
    feld[name] = (...a) => eigen.apply(api.aktiv, a);
  }

  const api = {
    zeigen(an) {
      const hatte = document.activeElement === api.aktiv;
      klar.value = feld.value;
      klar.hidden = !an;
      feld.hidden = an;
      if (hatte) api.aktiv.focus();
    },
    get sichtbar() { return !klar.hidden; },
    get aktiv() { return klar.hidden ? feld : klar; }
  };
  feld._aufdeckbar = api;
  return api;
}
