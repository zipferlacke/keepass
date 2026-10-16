/**
 * aufdecken.js — ein Passwortfeld sichtbar machen, als echtes Textfeld.
 *
 * `type` von „password" auf „text" zu stellen genügt nicht: Der Browser
 * merkt sich, dass das Feld einmal ein Passwortfeld war, und sagt das der
 * Bildschirmtastatur weiter. Auf dem Handy fehlen dann genau die Hilfen,
 * für die man das Feld aufgedeckt hat — Markieren, Kopieren, die
 * Zwischenablage der Tastatur.
 *
 * Deshalb bekommt das Feld einen Zwilling: ein Textfeld, das nie etwas
 * anderes war. Aufgedeckt steht der Zwilling an seiner Stelle, verdeckt
 * wieder das Passwortfeld. Beide führen denselben Wert.
 *
 * Für den Rest des Programms bleibt das Passwortfeld das Feld: Es behält
 * `id` und `name`, und was im Zwilling getippt wird, kommt dort als
 * gewöhnliches `input`-Ereignis an. Wer `feld.value` setzt, setzt beide.
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
  // Ein Geheimnis: nichts vorschlagen, nichts verbessern, nichts merken.
  klar.autocomplete = 'off';
  klar.autocapitalize = 'off';
  klar.spellcheck = false;
  klar.setAttribute('autocorrect', 'off');
  klar.dataset.klartext = '';
  klar.hidden = true;
  feld.after(klar);

  // Vom Zwilling zum Feld — als käme die Eingabe von dort.
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

  // Was das Programm am Feld einstellt, gilt auch für den Zwilling:
  // Platzhalter, gesperrt, Art der Tastatur.
  const MIT = ['placeholder', 'disabled', 'inputmode', 'required', 'minlength', 'maxlength'];
  new MutationObserver(aenderungen => {
    for (const { attributeName: name } of aenderungen) {
      if (feld.hasAttribute(name)) klar.setAttribute(name, feld.getAttribute(name));
      else klar.removeAttribute(name);
    }
  }).observe(feld, { attributes: true, attributeFilter: MIT });
  if (feld.hasAttribute('inputmode')) klar.setAttribute('inputmode', feld.getAttribute('inputmode'));
  if (feld.disabled) klar.disabled = true;

  // Fokus und Fehlermeldung landen bei dem Feld, das gerade zu sehen ist.
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
