/**
 * melden.js — alles, was im Browser passiert, geht als Text an den Server.
 *
 * Die Testseiten binden das ganz oben ein. Danach landet jede Meldung der
 * Konsole, jeder Fehler und jede abgelehnte Zusage im Protokoll von
 * `tests/lib/lauf.sh` — niemand muss Bilder lesen.
 */
export function melde(art, text) {
  // Der Fänger im Kopf der Seite meldet schon alles — dann nicht doppelt.
  if (typeof window.__melde === 'function') { window.__melde(art, text); return; }
  try { navigator.sendBeacon('/__log', `${art}\t${text}`); } catch { /* egal */ }
}

export function fangeAlles() {
  for (const art of ['log', 'info', 'warn', 'error']) {
    const alt = console[art].bind(console);
    console[art] = (...a) => {
      melde(art.toUpperCase(), a.map(x => x?.stack ?? String(x)).join(' '));
      alt(...a);
    };
  }
  addEventListener('error', e => melde('ERROR',
    e.error?.stack ?? `${e.message} @ ${e.filename ?? ''}:${e.lineno ?? ''}`), true);
  addEventListener('unhandledrejection', e => melde('ERROR',
    `unbehandelt: ${e.reason?.stack ?? e.reason}`));
}

/**
 * Klickt eine Folge von Schritten durch. „#feld:::wert" schreibt in ein
 * Feld, alles andere wird geklickt — drei Doppelpunkte, weil in einem
 * Selektor fast alles andere vorkommen kann. Zwischen den Schritten eine
 * kurze Pause, damit die Oberfläche nachkommt.
 */
export async function schritte(liste, pause = 700) {
  const warte = ms => new Promise(r => setTimeout(r, ms));
  await warte(900);
  for (const schritt of liste) {
    const teil = schritt.indexOf(':::');
    const wahl = teil > 0 ? schritt.slice(0, teil) : schritt;
    const el = document.querySelector(wahl);
    if (!el) { melde('ERROR', `Schritt ohne Ziel: ${wahl}`); continue; }
    melde('SCHRITT', schritt);
    if (teil > 0) {
      el.value = schritt.slice(teil + 3);
      el.dispatchEvent(new Event('input', { bubbles: true }));
      el.dispatchEvent(new Event('change', { bubbles: true }));
    } else {
      el.click();
    }
    await warte(pause);
  }
  melde('FERTIG', 'alle Schritte durch');
}
