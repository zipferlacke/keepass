/**
 * request.js — das kleine Fenster für Anfragen aus dem Browser.
 *
 * Es lebt für sich: eigene Seite, eigenes Fenster, kein Zustand aus der
 * Anwendung. Das ist Absicht — es geht auf, während man im Browser in einem
 * Anmeldeformular steht, und soll sofort da sein.
 *
 * Es beantwortet zwei verschiedene Fragen:
 *
 *   **Entsperren** (`kind: "unlock"`) — die Datenbank ist zu, ein Browser
 *   wartet. Hier wird sie geöffnet, mit PIN, Master-Passwort oder Finger.
 *   Auch das gehört in dieses Fenster und nicht in den Browser: Das
 *   Master-Passwort darf nicht durch Code wandern, den eine Website
 *   beeinflusst. Und die Anwendung muss dafür nicht offen stehen.
 *
 *   **Herausgabe** — die Datenbank ist offen, es geht um die Erlaubnis. Wie
 *   schwer die wiegt, gibt der Kern vor:
 *
 *     `confirm`    Ein Knopfdruck: Abbrechen oder Übernehmen.
 *     `identify`   Nachweis, dass **du** am Gerät bist. Die Voreinstellung.
 *
 * Die Stufe „Nichts" kommt hier nie an: Dann fragt der Kern gar nicht erst.
 * Einstellen lässt sie sich trotzdem von hier aus.
 *
 * Beides hintereinander wird nicht verlangt. Wer gerade entsperrt oder
 * bestätigt hat, wird eine Weile in Ruhe gelassen (`browser.graceSeconds`,
 * Voreinstellung eine Minute) — das Entsperren ist schon der Nachweis.
 * Diese Frist führt der Kern.
 */

import { invoke, listen } from './platform.js';
import { applyAppearance } from './theme.js';
import * as settings from './settings.js';

const $ = sel => document.querySelector(sel);
const esc = s => String(s ?? '').replace(/[&<>"']/g,
  c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

let current = null;

/**
 * Welche Nachweise dieses Gerät hergibt.
 *
 * Angeboten wird nur, was es wirklich gibt — ein Knopf, der nie funktioniert,
 * ist schlimmer als keiner.
 *
 * Die PIN wird dabei zweimal verschieden gemessen, und das ist kein
 * Versehen:
 *
 *   Zum **Entsperren** ist sie ein Schlüssel. Sie zählt nur, wenn diese
 *   Datenbank ausdrücklich dafür freigeschaltet ist (`pin`).
 *
 *   Zum **Bestätigen** ist sie ein Nachweis. Da genügt, dass überhaupt eine
 *   festgelegt ist (`pinSet`) — geöffnet wird damit nichts.
 */
const METHODEN = {
  pin: { label: 'PIN' },
  master: { label: 'Master-Passwort' }
};

let wege = {};
let verfuegbar = [];
let gewaehlt = 'master';

/* =========================================================
   Was in der Anfrage steht
   ========================================================= */

const TEXTE = {
  unlock: () => 'Die Datenbank ist gesperrt. Ein Browser wartet darauf.',
  logins: req => `${esc(req.client ?? 'Ein Browser')} möchte Benutzername und Passwort einsetzen.`,
  totp: req => `${esc(req.client ?? 'Ein Browser')} möchte einen Einmalcode abrufen.`,
  create: () => 'Ein neuer Eintrag soll angelegt werden.',
  update: () => 'Das Passwort soll geändert werden.',
  delete: () => 'Ein Eintrag soll in den Papierkorb wandern.',
  'passkey-register': () => 'Ein Passkey soll angelegt werden.',
  'passkey-get': () => 'Mit einem Passkey soll angemeldet werden.'
};

const ICONS = {
  unlock: 'lock_open',
  logins: 'key',
  totp: 'timer',
  create: 'add',
  update: 'edit',
  delete: 'delete',
  'passkey-register': 'passkey',
  'passkey-get': 'passkey'
};

function render(req) {
  current = req;
  zeige('#request');

  const entsperren = req.kind === 'unlock';

  $('#req-icon').textContent = ICONS[req.kind] ?? 'shield_person';
  $('#req-title').textContent = entsperren ? 'Datenbank entsperren' : 'Anfrage aus dem Browser';
  // Beim Entsperren steht hier, **welche** Datei geöffnet wird; sonst, wer
  // fragt. Beides beantwortet dieselbe Frage: worum geht es gerade?
  $('#req-host').textContent = (entsperren ? datenbank().name : req.host) ?? '';
  $('#req-text').innerHTML = (TEXTE[req.kind] ?? (() => 'Zugriff auf die Datenbank.'))(req);

  // Weicht das Ziel des Formulars vom besuchten Rechner ab, ist das das
  // klassische Merkmal einer untergeschobenen Anmeldemaske. Das gehört
  // sichtbar hierher, nicht ins Kleingedruckte.
  const warnung = $('#req-warning');
  warnung.hidden = !req.mismatch;
  if (req.mismatch) {
    warnung.innerHTML = `<strong>Achtung:</strong> Das Formular geht an
      <code>${esc(req.submitUrl ?? '')}</code> — nicht an die besuchte Seite.`;
  }

  const liste = $('#req-entries');
  const eintraege = req.entries ?? [];
  liste.hidden = eintraege.length === 0;
  liste.innerHTML = eintraege.map(e =>
    `<li>${esc(e.name || '(ohne Namen)')}${e.login ? ` — ${esc(e.login)}` : ''}</li>`).join('');

  // Entsperren verlangt immer einen Schlüssel — da gibt es kein „nur
  // bestätigen". Sonst entscheidet die eingestellte Stufe.
  const nachweis = entsperren || req.guard === 'identify';
  $('#req-identify').hidden = !nachweis;
  $('#req-allow').textContent = entsperren ? 'Entsperren' : 'Übernehmen';

  if (nachweis) zeigeMethoden(req.kind);
  (nachweis ? $('#req-secret') : $('#req-allow')).focus();
}

/** Die Datenbank, um die es geht — Name und Pfad. */
function datenbank() {
  const path = settings.get('database.current', null);
  const liste = settings.get('database.recent', []);
  const treffer = Array.isArray(liste) ? liste.find(d => d?.path === path) : null;

  return {
    path,
    name: treffer?.name ?? (path ? path.split(/[\\/]/).pop() : 'Keine ausgewählt')
  };
}

/** Zeigt genau einen der beiden Bereiche. */
function zeige(sel) {
  for (const teil of ['#request', '#req-settings']) {
    $(teil).hidden = teil !== sel;
  }
}

/* =========================================================
   Nachweise
   ========================================================= */

/**
 * Fragt einmal beim Start ab, was für die aktuelle Datenbank freigeschaltet
 * ist. Kostet nichts — hier rechnet noch kein Argon2.
 */
async function ermittleMethoden() {
  try {
    wege = await invoke('unlock_methods', { path: datenbank().path }) ?? {};
  } catch {
    // Dann bleibt das Master-Passwort. Das geht immer.
    wege = {};
  }
}

/** Baut den Umschalter für die gerade gestellte Frage. */
function zeigeMethoden(kind) {
  verfuegbar = [];
  if (kind === 'unlock' ? wege.pin : wege.pinSet) verfuegbar.push('pin');
  verfuegbar.push('master');

  gewaehlt = verfuegbar[0];

  const umschalter = $('#req-methods');
  umschalter.hidden = verfuegbar.length < 2;
  umschalter.innerHTML = verfuegbar.map(name => `
    <label>
      <input type="radio" name="methode" value="${name}"
        ${name === gewaehlt ? 'checked' : ''}>${METHODEN[name].label}
    </label>`).join('');

  umschalter.querySelectorAll('[name="methode"]').forEach(el =>
    el.addEventListener('change', () => waehleMethode(el.value)));

  waehleMethode(gewaehlt);

  // Fingerabdruck nur, wenn er für diese Datenbank freigeschaltet **und**
  // ein Leser da ist. Beides prüft der Kern.
  //
  // Mit Geräteschlüssel (Windows Hello) genügt zum Entsperren die Freigabe
  // dieser Datenbank, zum Bestätigen schon ein eingerichtetes Hello.
  const geraet = kind === 'unlock' ? wege.device : wege.deviceAvailable;
  $('#req-bio').hidden = !(wege.biometric || geraet);
  $('#req-bio').dataset.method = kind === 'unlock' && wege.device ? 'device' : 'biometric';
  $('#req-bio-text').textContent =
    `Mit ${geraet ? wege.deviceLabel ?? 'Biometrie' : 'Fingerabdruck'} ${kind === 'unlock' ? 'entsperren' : 'bestätigen'}`;
}

function waehleMethode(name) {
  gewaehlt = name;

  const feld = $('#req-secret');
  feld.value = '';
  // Steht nur ein Weg zur Wahl, fehlt der Umschalter — dann muss der
  // Platzhalter sagen, was gemeint ist.
  feld.placeholder = METHODEN[name].label;
  feld.inputMode = name === 'pin' ? 'numeric' : 'text';
  feld.focus();
}

/** Prüft den Nachweis. */
async function pruefe(method, secret) {
  try {
    await invoke('confirm_presence', { reason: 'Zugriff aus dem Browser', method, secret });
    // Der Kern merkt sich das für die eingestellte Frist — wer gerade bestätigt hat,
    // soll nicht drei Formulare später wieder gefragt werden.
    await invoke('browser_identified');
    return true;
  } catch (err) {
    melde(err.message);
    return false;
  }
}

/**
 * Öffnet die Datenbank.
 *
 * `method` heißt hier `password` statt `master` — das ist die Schreibweise
 * von `vault_unlock`, und sie unterscheidet sich von der bei
 * `confirm_presence`. Beim Umbenennen einer der beiden Stellen gäbe es eine
 * stille Fehlfunktion, deshalb steht die Übersetzung hier ausdrücklich.
 *
 * Wer entsperrt hat, gilt damit als ausgewiesen: `browser_identified` setzt
 * die Schonfrist, und die Rückfrage, die gleich darauf folgt, entfällt. Ein
 * Vorgang, ein Dialog.
 */
async function entsperre(method, secret) {
  const { path } = datenbank();
  if (!path) {
    melde('Es ist keine Datenbank ausgewählt. Bitte einmal im Hauptfenster öffnen.');
    return false;
  }

  // Argon2 rechnet je nach Datenbank mehrere Sekunden. Ohne Rückmeldung
  // sieht das aus, als sei nichts passiert — und man drückt noch einmal.
  const fertig = arbeitet(true);

  try {
    await invoke('vault_unlock', {
      path,
      method: method === 'master' ? 'password' : method,
      secret,
      autoLockMinutes: Number(settings.get('unlock.autoLockMinutes', 5)) || 0
    });
    await invoke('browser_identified');
    return true;
  } catch (err) {
    melde(err.message);
    return false;
  } finally {
    fertig();
  }
}

/** Sperrt die Bedienelemente, solange gerechnet wird. */
function arbeitet(an) {
  const knoepfe = [$('#req-allow'), $('#req-deny'), $('#req-bio'), $('#req-secret')];
  const beschriftung = $('#req-allow').textContent;

  knoepfe.forEach(el => { el.disabled = an; });
  if (an) $('#req-allow').textContent = 'Einen Moment …';

  return () => {
    knoepfe.forEach(el => { el.disabled = false; });
    $('#req-allow').textContent = beschriftung;
  };
}

/** Zeigt einen Fehlschlag am Feld — dort, wo er entstanden ist. */
function melde(text) {
  const feld = $('#req-secret');
  feld.value = '';
  feld.setCustomValidity(text || 'Das hat nicht geklappt.');
  feld.reportValidity();
  feld.setCustomValidity('');
  feld.focus();
}

/* =========================================================
   Antworten
   ========================================================= */

async function answer(allow) {
  if (!current) return;

  const id = current.id;
  current = null;

  try {
    await invoke('browser_answer', { id, allow });
  } catch { /* Der Kern räumt selbst auf, wenn die Frist abläuft. */ }

  $('#request').hidden = true;
}

/* =========================================================
   Einstellungen im selben Fenster
   ========================================================= */

const NOTIZEN = {
  never: 'Verknüpfte Browser füllen ohne Rückfrage aus. Ab der nächsten Anfrage — diese hier will noch beantwortet werden.',
  confirm: 'Ein Knopfdruck genügt — Abbrechen oder Übernehmen, ohne Nachweis.',
  identify: 'PIN, Master-Passwort oder Fingerabdruck. Wie lange danach nicht erneut gefragt wird, steht in den Einstellungen.'
};

function zeigeEinstellungen() {
  const jetzt = settings.get('browser.guard', 'identify');

  $('#req-guard').querySelectorAll('[name="guard"]').forEach(el => {
    el.checked = el.value === jetzt;
  });
  $('#req-guard-note').textContent = NOTIZEN[jetzt] ?? '';

  zeige('#req-settings');
}

/* =========================================================
   Start
   ========================================================= */

async function boot() {
  // Einstellungen und Aussehen sind Beiwerk. Scheitern sie — etwa weil das
  // Fenster keine Berechtigung hat —, darf das nicht die ganze Seite
  // verhindern: Übrig bliebe ein schwarzes Fenster ohne jeden Hinweis.
  try {
    await settings.initSettings();
    applyAppearance(settings.get('appearance', {}));
  } catch (err) {
    console.error('Einstellungen nicht lesbar:', err);
  }

  await ermittleMethoden();

  // Zwei Wege zur Anfrage, und beide werden gebraucht.
  //
  // Das Ereignis ist der schnelle: Steht das Fenster schon und kommt eine
  // zweite Anfrage, ist sie sofort da. Beim allerersten Öffnen greift es
  // aber nicht — der Kern sendet, während diese Datei noch geladen wird.
  // Deshalb wird zusätzlich einmal aktiv nachgefragt.
  // Das Fenster wird nach einer Anfrage nur versteckt, nicht geschlossen —
  // es lebt also lange. Einstellungen und freigeschaltete Wege können sich
  // inzwischen im Hauptfenster geändert haben: vor jeder Anfrage neu lesen.
  await listen('browser-request', async ev => {
    try { await settings.reloadSettings(); } catch { /* alter Stand */ }
    await ermittleMethoden();
    render(ev?.payload ?? {});
  });

  try {
    const wartend = await invoke('browser_pending');
    if (wartend && !current) render(wartend);
  } catch (err) {
    console.error('Anfrage nicht abrufbar:', err);
    $('#req-title').textContent = 'Nicht erreichbar';
    $('#req-text').textContent = err.message;
    $('#req-identify').hidden = true;
    $('#req-allow').hidden = true;
    $('#req-deny').textContent = 'Schließen';
    zeige('#request');
  }

  $('#req-form').addEventListener('submit', async ev => {
    ev.preventDefault();
    if (!current) return;

    if (current.kind === 'unlock') {
      const secret = $('#req-secret').value;
      if (!secret || !(await entsperre(gewaehlt, secret))) return;
      return answer(true);
    }

    if (current.guard === 'identify') {
      const secret = $('#req-secret').value;
      if (!secret || !(await pruefe(gewaehlt, secret))) return;
      return answer(true);
    }

    answer(true);
  });

  $('#req-deny').addEventListener('click', () => answer(false));

  // Escape lehnt ab. Ein Fenster, das man nur wegklicken kann, ohne dass
  // klar ist was passiert, wäre die falsche Voreinstellung.
  document.addEventListener('keydown', ev => {
    if (ev.key !== 'Escape') return;
    if ($('#req-settings').hidden) answer(false);
    else zeige('#request');
  });

  $('#req-eye').addEventListener('click', () => {
    const feld = $('#req-secret');
    const sichtbar = feld.type === 'text';
    feld.type = sichtbar ? 'password' : 'text';
    $('#req-eye').querySelector('.msr').textContent = sichtbar ? 'visibility' : 'visibility_off';
    feld.focus();
  });

  $('#req-bio').addEventListener('click', async () => {
    const gelungen = current?.kind === 'unlock'
      ? await entsperre($('#req-bio').dataset.method ?? 'biometric', null)
      : await pruefe('biometric', null);

    if (gelungen) answer(true);
  });

  $('#req-gear').addEventListener('click', zeigeEinstellungen);
  $('#req-back').addEventListener('click', () => zeige('#request'));

  $('#req-guard').querySelectorAll('[name="guard"]').forEach(el =>
    el.addEventListener('change', async () => {
      await settings.set('browser.guard', el.value, { silent: true });
      $('#req-guard-note').textContent = NOTIZEN[el.value] ?? '';
    }));
}

boot();
