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
 *
 * Geprüft wird mit „?wahl" (muss zu sehen sein) und „!wahl" (darf nicht
 * zu sehen sein) — beides klickt nichts an.
 */
export async function schritte(liste, pause = 700) {
  const warte = ms => new Promise(r => setTimeout(r, ms));
  await warte(900);
  for (const schritt of liste) {
    // „@wahl" meldet Lage und Größe — für Abstände, die man sonst nur im
    // Bild sähe.
    if (schritt[0] === '@') {
      const el = document.querySelector(schritt.slice(1));
      if (!el) { melde('ERROR', `Nicht da: ${schritt}`); continue; }
      const r = el.getBoundingClientRect();
      const cs = getComputedStyle(el);
      melde('MASS', `${schritt.slice(1)}  x=${Math.round(r.x)} y=${Math.round(r.y)} b=${Math.round(r.width)} h=${Math.round(r.height)}  padding=${cs.padding}  margin=${cs.margin}`);
      continue;
    }

    // „~wahl:::dx/dy" zieht das Element um dx/dy Pixel (Zeiger runter,
    // bewegen, los) — etwa den Griff eines Dialogs.
    if (schritt[0] === '~') {
      const [wahl, weg] = schritt.slice(1).split(':::');
      const el = document.querySelector(wahl);
      if (!el) { melde('ERROR', `Schritt ohne Ziel: ${wahl}`); continue; }
      melde('SCHRITT', schritt);
      const [dx, dy] = (weg ?? '0/0').split('/').map(Number);
      const r = el.getBoundingClientRect();
      const x = r.x + r.width / 2, y = r.y + r.height / 2;
      const zeiger = (art, px, py) => el.dispatchEvent(new PointerEvent(art,
        { bubbles: true, cancelable: true, pointerId: 1, button: 0, isPrimary: true, clientX: px, clientY: py }));
      zeiger('pointerdown', x, y);
      for (let i = 1; i <= 5; i++) zeiger('pointermove', x + dx * i / 5, y + dy * i / 5);
      zeiger('pointerup', x + dx, y + dy);
      await warte(pause);
      continue;
    }

    // „?wahl" verlangt, dass etwas zu sehen ist, „!wahl", dass nicht.
    if (schritt[0] === '?' || schritt[0] === '!') {
      const el = document.querySelector(schritt.slice(1));
      // checkVisibility kennt auch zugeklappte <details> (content-visibility).
      const sichtbar = Boolean(el) && el.getClientRects().length > 0 && (el.checkVisibility?.() ?? true);
      if (sichtbar === (schritt[0] === '?')) melde('OK', schritt);
      else melde('ERROR', `Erwartung verfehlt: ${schritt}`);
      continue;
    }

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
