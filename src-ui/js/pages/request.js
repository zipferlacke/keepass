/**
 * request.js — das kleine Fenster für Anfragen aus dem Browser.
 *
 * Eigene Seite und eigenes Fenster, unabhängig vom Zustand der Anwendung.
 * Es beantwortet zwei Arten von Anfragen:
 *
 *   **Entsperren** (`kind: "unlock"`) — die Datenbank ist geschlossen und ein
 *   Browser wartet. Geöffnet wird mit PIN, Master-Passwort oder Fingerabdruck.
 *   Das Master-Passwort wird bewusst hier und nicht im Browser eingegeben.
 *
 *   **Herausgabe** — die Datenbank ist offen, gefragt wird nach der Erlaubnis.
 *   Die Stufe gibt der Kern vor:
 *
 *     `confirm`    Ein Knopfdruck: Abbrechen oder Übernehmen.
 *     `identify`   Nachweis der Anwesenheit am Gerät (Voreinstellung).
 *
 * Die Stufe „Nichts" erreicht dieses Fenster nie; sie lässt sich hier aber
 * einstellen. Nach einem Entsperren oder Bestätigen entfällt die Rückfrage
 * für eine Schonfrist (`browser.graceSeconds`, Voreinstellung eine Minute),
 * die der Kern führt.
 */

import { invoke, listen } from '../core/platform.js';
import { applyAppearance } from '../core/theme.js';
import * as settings from '../data/settings.js';
import { aufdeckbar } from '../ui/aufdecken.js';
import { initI18n, uebersetzeSeite, t } from '../core/i18n.js';

const $ = sel => document.querySelector(sel);
const esc = s => String(s ?? '').replace(/[&<>"']/g,
  c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

let current = null;

/**
 * Ermittelt, welche Nachweise dieses Gerät anbietet; nur vorhandene Wege werden gezeigt.
 *
 * Die PIN zählt je nach Anfrage unterschiedlich:
 *   Zum **Entsperren** ist sie ein Schlüssel und gilt nur, wenn die Datenbank
 *   dafür freigeschaltet ist (`pin`).
 *   Zum **Bestätigen** ist sie ein Nachweis; es genügt, dass eine PIN
 *   festgelegt ist (`pinSet`).
 */
const METHODEN = {
  pin: { label: () => t('anfrage.nachweis.pin') },
  master: { label: () => t('anfrage.nachweis.master') }
};

let wege = {};
let verfuegbar = [];
let gewaehlt = 'master';

/* =========================================================
   Was in der Anfrage steht
   ========================================================= */

const TEXTE = {
  unlock: () => t('anfrage.text.unlock'),
  // Statt des Verknüpfungsnamens steht die anfragende Seite im Kopf.
  logins: () => t('anfrage.text.logins'),
  totp: () => t('anfrage.text.totp'),
  create: () => t('anfrage.text.create'),
  update: () => t('anfrage.text.update'),
  delete: () => t('anfrage.text.delete'),
  'passkey-register': () => t('anfrage.text.passkeyRegister'),
  'passkey-get': () => t('anfrage.text.passkeyGet')
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
  $('#req-title').textContent = entsperren ? t('anfrage.titel.entsperren') : t('anfrage.titel.anfrage');
  // Beim Entsperren: Name der Datei; sonst: anfragender Host.
  $('#req-host').textContent = (entsperren ? datenbank().name : req.host) ?? '';
  $('#req-text').innerHTML = (TEXTE[req.kind] ?? (() => t('anfrage.text.sonst')))(req);

  // Weicht das Formularziel vom besuchten Host ab, erscheint eine Warnung.
  const warnung = $('#req-warning');
  warnung.hidden = !req.mismatch;
  if (req.mismatch) {
    warnung.innerHTML = t('anfrage.warnung', { ziel: `<code>${esc(req.submitUrl ?? '')}</code>` });
  }

  const liste = $('#req-entries');
  const eintraege = req.entries ?? [];
  liste.hidden = eintraege.length === 0;
  liste.innerHTML = eintraege.map(e =>
    `<li>${esc(e.name || t('anfrage.eintrag.ohneName'))}${e.login ? ` — ${esc(e.login)}` : ''}</li>`).join('');

  // Entsperren verlangt immer einen Schlüssel; sonst gilt die eingestellte Stufe.
  const nachweis = entsperren || req.guard === 'identify';
  $('#req-identify').hidden = !nachweis;
  $('#req-allow').textContent = entsperren ? t('anfrage.knoepfe.entsperren') : t('anfrage.knoepfe.uebernehmen');

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
    name: treffer?.name ?? (path ? path.split(/[\\/]/).pop() : t('anfrage.datenbank.keineAusgewaehlt'))
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

/** Liest einmal beim Start, was für die aktuelle Datenbank freigeschaltet ist. */
async function ermittleMethoden() {
  try {
    wege = await invoke('unlock_methods', { path: datenbank().path }) ?? {};
  } catch {
    // Rückfall: Master-Passwort.
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
        ${name === gewaehlt ? 'checked' : ''}>${METHODEN[name].label()}
    </label>`).join('');

  umschalter.querySelectorAll('[name="methode"]').forEach(el =>
    el.addEventListener('change', () => waehleMethode(el.value)));

  waehleMethode(gewaehlt);

  // Fingerabdruck: Freigabe für die Datenbank und ein vorhandener Leser (Prüfung im Kern).
  // Gerätenachweis (Windows Hello): zum Entsperren muss die Datenbank freigeschaltet sein,
  // zum Bestätigen genügt ein eingerichtetes Hello.
  const geraet = kind === 'unlock' ? wege.device : wege.deviceAvailable;
  $('#req-bio').hidden = !(wege.biometric || geraet);
  $('#req-bio').dataset.method = kind === 'unlock' && wege.device ? 'device' : 'biometric';
  $('#req-bio-text').textContent =
    t(kind === 'unlock' ? 'anfrage.nachweis.bioEntsperren' : 'anfrage.nachweis.bioBestaetigen',
      { name: geraet ? wege.deviceLabel ?? t('anfrage.nachweis.biometrie') : t('anfrage.nachweis.fingerabdruck') });
}

function waehleMethode(name) {
  gewaehlt = name;

  const feld = $('#req-secret');
  feld.value = '';
  // Bei nur einem Weg fehlt der Umschalter; der Platzhalter benennt ihn.
  feld.placeholder = METHODEN[name].label();
  feld.inputMode = name === 'pin' ? 'numeric' : 'text';
  feld.focus();
}

/** Prüft den Nachweis. */
async function pruefe(method, secret) {
  try {
    await invoke('confirm_presence', { reason: t('anfrage.nachweis.grund'), method, secret });
    // Der Kern merkt sich den Nachweis für die eingestellte Schonfrist.
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
 * `method` heißt hier `password` (Schreibweise von `vault_unlock`), bei
 * `confirm_presence` dagegen `master`. Nach dem Entsperren setzt
 * `browser_identified` die Schonfrist, eine weitere Rückfrage entfällt.
 */
async function entsperre(method, secret) {
  const { path } = datenbank();
  if (!path) {
    melde(t('anfrage.fehler.keineDatenbank'));
    return false;
  }

  // Argon2 braucht je nach Datenbank mehrere Sekunden; solange läuft die Rückmeldung.
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
  if (an) $('#req-allow').textContent = t('anfrage.knoepfe.einMoment');

  return () => {
    knoepfe.forEach(el => { el.disabled = false; });
    $('#req-allow').textContent = beschriftung;
  };
}

/** Zeigt einen Fehlschlag am Feld — dort, wo er entstanden ist. */
function melde(text) {
  const feld = $('#req-secret');
  feld.value = '';
  feld.setCustomValidity(text || t('anfrage.fehler.nichtGeklappt'));
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

  // Wartet eine weitere Anfrage, wird sie sofort angezeigt.
  try {
    const naechste = await invoke('browser_pending');
    if (naechste && !current) render(naechste);
  } catch { /* dann eben nicht */ }
}

/* =========================================================
   Einstellungen im selben Fenster
   ========================================================= */

const notizen = () => ({
  never: t('anfrage.einstellungen.notizNever'),
  confirm: t('anfrage.einstellungen.notizConfirm'),
  identify: t('anfrage.einstellungen.notizIdentify')
});

/** Beschriftet die drei Stufen — der Text steht direkt hinter dem Kreis. */
function beschrifteStufen() {
  const namen = { never: 'nichts', confirm: 'bestaetigen', identify: 'legitimieren' };
  $('#req-guard').querySelectorAll('[name="guard"]').forEach(el => {
    el.nextSibling.textContent = t(`anfrage.einstellungen.${namen[el.value]}`); // i18n: anfrage.einstellungen.nichts anfrage.einstellungen.bestaetigen anfrage.einstellungen.legitimieren
  });
}

function zeigeEinstellungen() {
  const jetzt = settings.get('browser.guard', 'identify');

  $('#req-guard').querySelectorAll('[name="guard"]').forEach(el => {
    el.checked = el.value === jetzt;
  });
  $('#req-guard-note').textContent = notizen()[jetzt] ?? '';

  zeige('#req-settings');
}

/* =========================================================
   Start
   ========================================================= */

async function boot() {
  // Einstellungen und Aussehen sind optional; ein Fehler blockiert die Seite nicht.
  try {
    await settings.initSettings();
    applyAppearance(settings.get('appearance', {}));
  } catch (err) {
    console.error('Einstellungen nicht lesbar:', err);
  }

  // Sprache vor dem ersten Zeichnen laden (ohne lesbare Einstellungen: „auto").
  try {
    await initI18n(settings.get('appearance.language', 'auto'));
  } catch (err) {
    console.error('Sprache nicht ladbar:', err);
  }
  uebersetzeSeite();
  beschrifteStufen();

  await ermittleMethoden();

  // Anfragen kommen auf zwei Wegen: als Ereignis (bei bereits offenem Fenster) und
  // durch einmaliges aktives Nachfragen (beim ersten Öffnen sendet der Kern, bevor
  // dieses Skript geladen ist). Das Fenster wird nach einer Anfrage nur versteckt;
  // Einstellungen und Wege werden deshalb vor jeder Anfrage neu gelesen.
  await listen('browser-request', async ev => {
    // Bei bereits angezeigter Anfrage wartet die neue bis zur Antwort (siehe answer).
    if (current) return;
    try { await settings.reloadSettings(); } catch { /* alter Stand */ }
    try {
      await initI18n(settings.get('appearance.language', 'auto'));
      uebersetzeSeite();
      beschrifteStufen();
    } catch { /* alte Sprache */ }
    await ermittleMethoden();
    render(ev?.payload ?? {});
  });

  try {
    const wartend = await invoke('browser_pending');
    if (wartend && !current) render(wartend);
  } catch (err) {
    console.error('Anfrage nicht abrufbar:', err);
    $('#req-title').textContent = t('anfrage.fehler.nichtErreichbar');
    $('#req-text').textContent = err.message;
    $('#req-identify').hidden = true;
    $('#req-allow').hidden = true;
    $('#req-deny').textContent = t('allgemein.knoepfe.schliessen');
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

  // Beim Aktivieren des Fensters erhält das Eingabefeld den Fokus.
  window.addEventListener('focus', () => {
    const feld = aufdeckbar($('#req-secret')).aktiv;
    if (current && !$('#req-identify').hidden && document.activeElement !== feld) feld.focus();
  });

  // Escape lehnt ab.
  document.addEventListener('keydown', ev => {
    if (ev.key !== 'Escape') return;
    if ($('#req-settings').hidden) answer(false);
    else zeige('#request');
  });

  $('#req-eye').addEventListener('click', () => {
    const feld = aufdeckbar($('#req-secret'));
    const sichtbar = feld.sichtbar;
    feld.zeigen(!sichtbar);
    $('#req-eye').querySelector('.msr').textContent = sichtbar ? 'visibility' : 'visibility_off';
    feld.aktiv.focus();
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
      $('#req-guard-note').textContent = notizen()[el.value] ?? '';
    }));
}

boot();
