import * as vault from './vault.js';
import * as settings from './settings.js';
import { parseOtpauth, buildOtpauth } from './totp.js';
import { checkPwnedByHash, checkEmailBreached, passwordStrength as localStrength } from './security.js';
import { applyAppearance, applyTheme, applyPrimary, resolvedColor } from './theme.js';
import { avatarMarkup, refreshEpoch, hostFromUrl } from './icons.js';
import * as qr from './qr.js';
import * as preview from './preview.js';
import { enableDragMove } from './dragmove.js';
import * as pick from './multiselect.js';
import { isTauri, invoke, unlockMethods, pickDatabaseFile, pickSavePath, listen } from './platform.js';
import { dialog, banner, closeHostDialog, tableview } from './ui.js';

/* =========================================================
   Zustand
   ========================================================= */
const state = {
  view: 'home',
  entries: [],
  search: '',
  tag: null,
  kindFilter: null,
  expanded: new Set(),
  pwned: new Map(),
  reused: new Set(),
  strength: new Map(),
  codes: new Map(),
  emailFindings: [],
  checkRunning: false,
  lastCheck: null,
  dialogAttachments: [],
  secretEdits: null,
  locked: true,
  /** Was der Kern zum Entsperren anbietet — wird beim Start abgefragt. */
  unlock: { password: true, pin: false, biometric: false, device: false, deviceAvailable: false, deviceLabel: null },
  /** Welcher Eintrag gerade im Dialog offen ist — für „zuletzt genutzt". */
  dialogEntryId: null
};

const $ = sel => document.querySelector(sel);
const $$ = sel => [...document.querySelectorAll(sel)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

/** Anzeige für ein gesetztes, noch nicht geladenes Geheimnis. */
const SECRET_MASK = '•••••';

const VIEW_TITLES = {
  home: 'Übersicht', passwords: 'Passwörter', totp: 'TOTP-Codes',
  security: 'Sicherheitscheck', settings: 'Einstellungen'
};

/* =========================================================
   Start
   ========================================================= */
async function boot() {
  await settings.initSettings();
  applyAppearance(settings.get('appearance', {}));

  // Wurde die Anwendung durch einen Doppelklick auf eine .kdbx-Datei
  // gestartet, ist das die gemeinte Datenbank — noch vor der zuletzt
  // benutzten. Der Kern prüft dabei, dass die Datei wirklich existiert.
  await adoptStartupDatabase();

  state.expanded = new Set(settings.get('ui.expandedFolders', []));
  state.unlock = await unlockMethods();

  // Der Kern sperrt sich selbst, wenn zu lange nichts passiert — ein Timer
  // im Fenster liefe nicht zuverlässig weiter, wenn es im Hintergrund liegt.
  await listen('vault-locked', ev => {
    if (state.locked) return;
    showLockscreen(String(ev?.payload ?? 'Wegen Untätigkeit gesperrt.'));
  });

  // Abrufe über die Browser-Erweiterung zählen ebenfalls als Nutzung.
  await listen('entries-used', ev => markUsed(ev?.payload ?? []));

  await bindBrowserRequests();
  await bindFileDrops();
  bindStaticEvents();

  // Ändert sich die Auswahl, wird die Liste neu gezeichnet — dabei
  // erscheinen oder verschwinden die Kästchen.
  pick.onSelectionChange(() => {
    renderAll({ includeSettings: false });
    renderSelectionBar();
  });

  // Schmale Steuerfläche für tauri-agent-tools (siehe tools/screenshots.sh).
  // ES-Module haben einen eigenen Bereich, `eval` von außen käme sonst nicht
  // an `showView` heran. Bewusst nur Ansichtswechsel und Lesen — nichts, was
  // Geheimnisse herausgibt.
  window.showView = showView;
  window.wkeepass = {
    showView,
    view: () => state.view,
    ready: () => !state.locked,
    entryCount: () => state.entries.length
  };

  await showLockscreen();

  // Beim allerersten Start einmal durch die Einrichtung führen.
  if (!settings.get('ui.welcomeSeen', false)) await showWelcome();
  renderLockscreen();

  // Ist die Datenbank an das Gerät gebunden (Windows Hello), wird gleich
  // gefragt — das ersetzt PIN und Master-Passwort. Nur beim Programmstart:
  // Nach einem Sperren von Hand soll nicht sofort wieder etwas aufgehen.
  if (state.unlock.device && settings.get('database.current', null)) unlock({ method: 'device' });
}

/** Wie der gerätegebundene Weg heißt, etwa „Windows Hello". */
function deviceName() {
  return state.unlock.deviceLabel ?? 'Biometrie';
}

/**
 * Entsperren anstoßen: mit Geräteschlüssel direkt, sonst über den Dialog.
 */
function startUnlock() {
  if (state.unlock.device) unlock({ method: 'device' });
  else openUnlockDialog();
}

/**
 * Übernimmt die Datenbank, mit der die Anwendung aufgerufen wurde.
 *
 * Sie wird nur ausgewählt, nicht geöffnet — das Master-Passwort will ja
 * trotzdem eingegeben werden. Der Sperrbildschirm zeigt danach den richtigen
 * Namen, und die Datei landet gleich unter „zuletzt genutzt".
 */
async function adoptStartupDatabase() {
  let path = null;
  try { path = await vault.startupDatabase(); } catch { return; }
  if (!path || path === settings.get('database.current', null)) return;

  await settings.set('database.current', path, { silent: true });
  await rememberDatabase({ name: path.split(/[\\/]/).pop(), path });
}

/* =========================================================
   Anfragen aus dem Browser
   ---------------------------------------------------------
   Die Rückfrage selbst zeichnet ein **eigenes kleines Fenster**
   (`request.html`), das der Kern mittig über dem Browser aufgehen lässt.
   Wer dort in einem Anmeldeformular steht, soll nicht in die ganze
   Anwendung geworfen werden.

   Auch das Entsperren läuft dort. Hier bleibt nur der Fall, dass das
   Hauptfenster daneben offen steht: Es soll dann mitbekommen, was drüben
   passiert, statt auf dem Sperrbildschirm hängenzubleiben.
   ========================================================= */

async function bindBrowserRequests() {
  await listen('browser-needs-unlock', () => {
    if (!state.locked) return;
    banner('Ein Browser wartet auf die Datenbank.', 'info', 8000);
  });

  // Entsperrt wurde anderswo — im kleinen Fenster. Ohne das bliebe hier der
  // Sperrbildschirm stehen, obwohl die Datenbank längst offen ist.
  //
  // Der Fall „dieses Fenster hat selbst entsperrt" ist damit schon
  // abgehakt: Dann ist `state.locked` bereits false.
  await listen('vault-unlocked', async () => {
    if (!state.locked || unlockBusy()) return;

    // Erst übernehmen, dann anzeigen. Ohne das hält `vault.js` die Datenbank
    // weiter für geschlossen und liefert eine leere Liste — das Fenster käme
    // fertig, aber ohne einen einzigen Eintrag.
    await vault.adopt();

    await enterUnlocked();
    banner('Aus dem Browser entsperrt.', 'success', 4000);
  });

  // Die Erweiterung darf schreiben — verknüpfen, Einträge anlegen, Passkeys.
  // Der Kern schreibt das gleich zurück; klappt das nicht, wäre die Arbeit
  // beim nächsten Sperren weg. Das muss man erfahren.
  await listen('browser-save-failed', ev => {
    banner(`Änderung aus dem Browser nicht gespeichert: ${ev?.payload ?? ''}`, 'error', 10000);
  });
}

/** Holt Metadaten, Stärkewerte und Mehrfachnutzung neu aus dem Kern. */
async function refreshFromVault() {
  state.entries = await vault.listEntries();
  state.strength = settings.get('checks.passwordStrength', true)
    ? await vault.strengthMap()
    : new Map();
  state.reused = settings.get('checks.reuseDetection', true)
    ? await vault.reusedIds()
    : new Set();
}

/**
 * Leiste am unteren Rand, solange etwas ausgewählt ist.
 *
 * Sie zeigt, wie viele es sind, und bietet den Weg heraus — sonst käme man
 * auf dem Handy aus dem Auswahlmodus nicht mehr zurück.
 */
function renderSelectionBar() {
  let bar = $('#selection-bar');
  const count = pick.selectedIds().length;

  if (!count) { bar?.remove(); return; }

  if (!bar) {
    bar = document.createElement('div');
    bar.id = 'selection-bar';
    bar.className = 'selection-bar';
    document.body.append(bar);
  }

  bar.innerHTML = `
    <span class="selection-count">${count} ausgewählt</span>
    <button type="button" class="button" id="sel-move"><span class="msr">drive_file_move</span>&nbsp;Verschieben …</button>
    <button type="button" class="button" id="sel-delete" data-danger><span class="msr">delete</span>&nbsp;Löschen</button>
    <button type="button" class="button" data-shape="square no-background" id="sel-clear" title="Auswahl aufheben"><span class="msr">close</span></button>`;

  $('#sel-clear').onclick = () => pick.clearSelection();
  $('#sel-move').onclick = moveSelection;
  $('#sel-delete').onclick = deleteSelection;
}

/** Verschiebt alles Ausgewählte in einen Ordner. */
async function moveSelection() {
  const ids = pick.selectedIds();
  if (!ids.length) return;

  const fields = captureFields('folder');

  const res = await dialog({
    title: `${ids.length} ${ids.length === 1 ? 'Eintrag' : 'Einträge'} verschieben`,
    content: `<label class="field-label">Zielordner</label>
      <input list="move-folders" name="folder" placeholder="Ordner" autocomplete="off" required>
      <datalist id="move-folders">${vault.folders().map(f => `<option value="${esc(f)}">`).join('')}</datalist>`,
    confirmText: 'Verschieben',
    cancelText: 'Abbrechen',
    onInsert: fields.onInsert
  });

  const folder = fields.value('folder', res?.data);
  if (!res?.submit || !folder) return;

  for (const id of ids) await vault.moveEntry(id, folder);
  await vault.commit();

  pick.clearSelection();
  await refreshFromVault();
  renderAll({ includeSettings: false });
  banner(`${ids.length} verschoben.`, 'success');
}

/** Löscht alles Ausgewählte — in den Papierkorb, oder endgültig, wenn es schon drin liegt. */
async function deleteSelection() {
  const ids = pick.selectedIds();
  if (!ids.length) return;

  const inBin = ids.every(id => vault.getEntry(id)?.recycled);
  let confirmed = false;

  try {
    const res = await dialog({
      title: `${ids.length} ${ids.length === 1 ? 'Eintrag' : 'Einträge'} löschen`,
      content: inBin
        ? 'Diese Einträge liegen bereits im Papierkorb und werden endgültig entfernt. Das lässt sich nicht rückgängig machen.'
        : 'Die Einträge wandern in den Papierkorb und lassen sich von dort wiederherstellen.',
      confirmText: inBin ? 'Endgültig löschen' : 'In den Papierkorb',
      cancelText: 'Abbrechen'
    });
    confirmed = res?.submit ?? res === true;
  } catch { confirmed = false; }
  if (!confirmed) return;

  for (const id of ids) await vault.deleteEntry(id);
  await vault.commit();

  pick.clearSelection();
  await refreshFromVault();
  renderAll({ includeSettings: false });
  banner(`${ids.length} ${ids.length === 1 ? 'Eintrag' : 'Einträge'} gelöscht.`, 'success');
}

/**
 * Einträge ohne den Papierkorb.
 *
 * Was gelöscht ist, bleibt sichtbar — aber ein schwaches Passwort im
 * Papierkorb ist kein Befund, sondern Altlast. Alle Auswertungen laufen
 * deshalb hierüber.
 */
function liveEntries() {
  return state.entries.filter(e => !e.recycled);
}

/* =========================================================
   Sperren und Entsperren
   ========================================================= */

function recentDatabases() {
  const list = settings.get('database.recent', []);
  return Array.isArray(list) ? list : [];
}

async function rememberDatabase(entry) {
  const list = recentDatabases().filter(d => d.path !== entry.path);
  list.unshift(entry);
  await settings.set('database.recent', list.slice(0, 5), { silent: true });
  await settings.set('database.current', entry.path, { silent: true });
}

/**
 * Räumt die Ansicht hinter dem Sperrbildschirm ab.
 *
 * Der Sperrbildschirm legt sich nur darüber; was darunter aktiv war, bleibt
 * es. Wer aus den Einstellungen heraus sperrt, hätte darunter also weiter
 * die volle Einstellungsseite stehen — und weil die länger ist als das
 * Fenster, wächst die Seite mit und lässt sich scrollen.
 *
 * `showView` hilft hier nicht: Es steigt bei gesperrter Datenbank aus.
 * Deshalb von Hand, und an einer Stelle für alle Wege dorthin.
 */
function resetToHomeView() {
  state.view = 'home';
  $$('.view').forEach(v => v.toggleAttribute('data-active', v.id === 'view-home'));
  const body = $('#settings-body');
  if (body) body.innerHTML = '';
}

async function showLockscreen(message = null) {
  state.locked = true;
  document.body.dataset.locked = 'true';
  resetToHomeView();
  $('#lockscreen').hidden = false;
  $('#btn-add').hidden = true;

  // Frisch nachfragen: Ob es eine PIN gibt, kann sich seit dem Start
  // geändert haben — etwa weil man sie gerade eingerichtet hat.
  const current = settings.get('database.current', null);
  try { state.unlock = await unlockMethods(current); } catch { /* Voreinstellung behalten */ }

  renderLockscreen(message);
}

// Markenzeichen als Bilddatei. Zur Farbe des W siehe logo.svg selbst —
// ein über <img> geladenes SVG erbt nichts von dieser Seite.
const BRAND_MARK = `<img class="lock-mark" src="./logo.svg" alt="" width="128" height="128">`;

/**
 * Sperrbildschirm.
 *
 * Aufbau von oben nach unten: aktuelle Datenbank, Entsperren, neue Datenbank
 * anlegen, und ganz unten zugeklappt die zuletzt genutzten. Welcher Weg zum
 * Entsperren erscheint, entscheidet der Kern über `unlock_methods` — hier
 * wird nur angezeigt, was er anbietet.
 */
function renderLockscreen(message) {
  // Nach einem erfolgreichen Entsperren bleibt die Beschäftigt-Markierung
  // sonst am Element hängen und die Karte wirkt beim nächsten Mal blockiert.
  $('#lock-card')?.removeAttribute('data-busy');

  const list = recentDatabases();
  const current = settings.get('database.current', null);
  const active = list.find(d => d.path === current);
  const others = list.filter(d => d.path !== current);

  $('#lock-card').innerHTML = `
    ${BRAND_MARK}
    <h2>WKeePass</h2>
    ${message ? `<p class="lock-sub">${esc(message)}</p>` : ''}

    ${active
      ? `<div class="lock-current">
           <span class="msr">database</span>
           <span class="lock-current-text">
             <strong>${esc(active.name)}</strong>
             <small>${esc(active.path)}</small>
           </span>
         </div>`
      : `<p class="lock-sub">Noch keine Datenbank ausgewählt</p>`}

    ${active ? `<div class="lock-actions lock-primary">
      ${state.unlock.device
        ? `<button class="button hightlight" data-shape="full" id="lock-device"><span class="msr">fingerprint</span>&nbsp;Mit ${esc(deviceName())} entsperren</button>
           <button class="button" data-shape="full" id="lock-unlock"><span class="msr">password</span>&nbsp;Mit Passwort oder PIN …</button>`
        : `<button class="button hightlight" data-shape="full" id="lock-unlock"><span class="msr">lock_open</span>&nbsp;Entsperren</button>`}
    </div>` : ''}

    <div class="lock-actions">
      <button class="button" data-shape="full" id="lock-pick"><span class="msr">folder_open</span>&nbsp;Datenbank auswählen …</button>
      <button class="button" data-shape="full" id="lock-new"><span class="msr">add</span>&nbsp;Neue Datenbank anlegen …</button>
    </div>

    ${list.length ? `<details class="lock-recent">
      <summary>
        <span class="msr">history</span>
        <span class="folder-name">Zuletzt genutzt</span>
        <span class="folder-count">${list.length}</span>
      </summary>
      <div class="lock-db-list">
        ${list.map(d => `
          <button type="button" class="lock-db" data-db="${esc(d.path)}" aria-pressed="${d.path === current}">
            <span class="lock-db-text"><strong>${esc(d.name)}</strong><small>${esc(d.path)}</small></span>
          </button>`).join('')}
      </div>
    </details>` : ''}`;

  // Ein Klick auf eine der zuletzt genutzten wählt sie aus und entsperrt gleich.
  $$('#lock-card .lock-db').forEach(btn => btn.addEventListener('click', async () => {
    await settings.set('database.current', btn.dataset.db, { silent: true });
    state.unlock = await unlockMethods(btn.dataset.db);
    renderLockscreen();
    startUnlock();
  }));

  // Das Zahnrad sitzt im Fenster, nicht in der Karte — einmal verkabeln reicht.
  $('#lock-gear').onclick = openSettingsPage;

  $('#lock-unlock')?.addEventListener('click', openUnlockDialog);
  $('#lock-device')?.addEventListener('click', () => unlock({ method: 'device' }));
  $('#lock-pick')?.addEventListener('click', pickDatabase);
  $('#lock-new')?.addEventListener('click', createDatabase);
}

/**
 * Fragt nach dem, was für diese Datenbank freigeschaltet ist.
 *
 * Ein Dialog statt drei Feldern auf der Karte: Der Sperrbildschirm bleibt
 * damit aufgeräumt, und es ist immer klar, welcher Weg gerade gemeint ist.
 */
async function openUnlockDialog() {
  const u = state.unlock;
  const fields = captureFields('pin', 'pw');

  const res = await dialog({
    title: 'Entsperren',
    content: `
      ${u.biometric ? `<button type="button" class="button hightlight" data-shape="full" id="dlg-bio">
        <span class="msr">fingerprint</span>&nbsp;Mit Fingerabdruck entsperren</button>` : ''}

      ${u.pin ? `<label class="field-label">App-PIN</label>
        ${passwordField('pin', 'PIN', { required: false })}` : ''}

      <label class="field-label">Master-Passwort${u.pin ? ' (falls die PIN nicht passt)' : ''}</label>
      ${passwordField('pw', 'Master-Passwort', { required: !u.pin })}

      ${u.deviceAvailable && !u.device ? `<div class="setting">
        <div class="setting-label"><strong>Künftig mit ${esc(deviceName())} öffnen</strong>
          <small>Ersetzt PIN und Master-Passwort auf diesem Gerät</small></div>
        <div class="setting-control"><input type="checkbox" data-shape="toggle" name="rememberDevice"
          ${settings.get('unlock.biometrics', true) ? 'checked' : ''}></div>
      </div>` : ''}

      ${u.pin || !u.pinSet ? '' : `<div class="setting">
        <div class="setting-label"><strong>Künftig auch mit PIN öffnen</strong></div>
        <div class="setting-control"><input type="checkbox" data-shape="toggle" name="remember"></div>
      </div>`}`,
    confirmText: 'Entsperren',
    cancelText: 'Abbrechen',
    onInsert: () => {
      fields.onInsert();
      queueMicrotask(() => {
        document.getElementById('dlg-bio')?.addEventListener('click', () => {
          closeHostDialog(document.getElementById('dlg-bio'), false);
          unlock({ method: 'biometric' });
        });
      });
    }
  });

  if (!res?.submit) return;
  const d = { pin: fields.value('pin', res.data), pw: fields.value('pw', res.data) };

  if (d.pin) { unlock({ method: 'pin', secret: d.pin }); return; }
  if (!d.pw) { banner('Bitte PIN oder Master-Passwort eingeben.', 'warning'); return; }

  const wantsPin = fieldChecked(res.data, 'remember');
  const wantsDevice = fieldChecked(res.data, 'rememberDevice');
  const pin = wantsPin ? await askAppPin() : '';

  unlock({
    method: 'password',
    secret: d.pw,
    remember: (wantsPin && pin) || wantsDevice
      ? { pin, allowPin: wantsPin && Boolean(pin), allowBiometric: false, allowDevice: wantsDevice }
      : null
  });
}

/** Kleine Nachfrage nach der App-PIN, wenn sie zum Bestätigen gebraucht wird. */
async function askAppPin() {
  const fields = captureFields('pin');

  const res = await dialog({
    title: 'App-PIN bestätigen',
    content: `<p>Zum Freischalten dieser Datenbank wird die PIN des Programms gebraucht.</p>
      ${passwordField('pin', 'App-PIN', { minlength: 4 })}`,
    confirmText: 'Bestätigen',
    cancelText: 'Abbrechen',
    onInsert: fields.onInsert
  });
  return res?.submit ? fields.value('pin', res.data) : '';
}

/**
 * Willkommensbildschirm beim allerersten Start.
 *
 * Danach steht die PIN des Programms, und der Sperrbildschirm kann sie
 * anbieten. Übergehen lässt sich das — dann geht jede Datenbank eben nur
 * mit ihrem Master-Passwort auf.
 */
async function showWelcome() {
  return new Promise(resolve => {
    $('#welcome').hidden = false;

    $('#welcome-card').innerHTML = `
      ${BRAND_MARK}
      <h2>Willkommen bei WKeePass</h2>
      <p class="lock-sub">Für die einfachere Verwendung der App kann eine <b>Pin</b> und/oder eine <b>Biometrie</b> genutzet werden zur Entschlüsselung der Daten und Bestätigung beim Entnehmen.
        Nach der Einrichtung kann pro Datenbank individuell die vereinfachte Entschlüsselung und Bestätigung eingestellt werden.
      </p>
      

      <div class="setting">
        <div class="setting-label">
          <strong>PIN einrichten</strong>
        </div>
        <div class="setting-control">
          <span class="pw-field">
            <input type="password" id="wc-pin" inputmode="numeric" placeholder="Mindestens vier Zeichen" autocomplete="off" minlength="4">
            <button type="button" class="pw-eye" title="Sichtbar machen" aria-label="Sichtbar machen"><span class="msr">visibility</span></button>
          </span>
          <span class="pw-field">
            <input type="password" id="wc-pin2" inputmode="numeric" placeholder="PIN wiederholen" autocomplete="off" minlength="4">
            <button type="button" class="pw-eye" title="Sichtbar machen" aria-label="Sichtbar machen"><span class="msr">visibility</span></button>
          </span>
        </div>
      </div>

      ${state.unlock.deviceAvailable
        ? `<div class="setting">
            <div class="setting-label">
              <strong>${esc(deviceName())} nutzen</strong>
              <small>Ersetzt PIN und Master-Passwort. Der Schlüssel liegt im Sicherheitschip dieses Geräts — eine PIN ist dann nur noch Rückfallweg.</small>
            </div>
            <div class="setting-control">
              <input type="checkbox" data-shape="toggle" id="wc-bio" checked>
            </div>
          </div>`
        : `<div class="setting">
            <div class="setting-label">
              <strong>Biometrie Entsperrung nutzen</strong>
              <small>${state.unlock.keyring ? '' : 'Auf dem Gerät nicht verfügbar'}</small>
            </div>
            <div class="setting-control">
              <input type="checkbox" data-shape="toggle" id="wc-bio" ${state.unlock.keyring ? '' : 'disabled'}>
            </div>
          </div>`}

      <div class="lock-actions">
        <button type="button" class="button hightlight" data-shape="full" id="wc-ok"><span class="msr">check</span>&nbsp;Einrichten</button>
        <button type="button" class="button" data-shape="full" id="wc-skip">Ohne PIN weiter</button>
      </div>`;

    wirePasswordFields($('#welcome-card'));

    const done = async () => {
      await settings.set('ui.welcomeSeen', true, { silent: true });
      $('#welcome').hidden = true;
      resolve();
    };

    $('#wc-skip').onclick = done;

    $('#wc-ok').onclick = async () => {
      const pin = $('#wc-pin').value.trim();
      const bio = $('#wc-bio').checked;
      // Mit Geräteschlüssel geht es auch ganz ohne PIN: Freigeschaltet wird
      // dann beim ersten Öffnen einer Datenbank.
      const deviceOnly = bio && state.unlock.deviceAvailable;

      if (!pin && !deviceOnly) { banner('Bitte eine PIN vergeben — oder „Ohne PIN weiter".', 'warning'); return; }
      if (pin && pin !== $('#wc-pin2').value.trim()) { banner('Die beiden PINs stimmen nicht überein.', 'warning'); return; }

      try {
        if (pin) await vault.createPin(pin);
        await settings.set('unlock.biometrics', bio, { silent: true });
        state.unlock = await unlockMethods(settings.get('database.current', null));
        banner(pin ? 'PIN festgelegt.' : `${deviceName()} wird beim ersten Öffnen eingerichtet.`, 'success');
        await done();
      } catch (err) {
        banner(err.message, 'error', 6000);
      }
    };
  });
}

async function pickDatabase() {
  const picked = await pickDatabaseFile();

  if (!picked) { banner('Es wurde keine Datei ausgewählt.', 'info'); return; }

  const name = String(picked).split(/[\\/]/).pop();
  await rememberDatabase({ name, path: picked });
  renderLockscreen();
}

/* =========================================================
   Die PIN des Programms
   ---------------------------------------------------------
   Eine PIN für alles, einmal festgelegt. Pro Datenbank wird dann nur noch
   entschieden, ob sie damit — oder per Fingerabdruck — aufgehen darf.
   ========================================================= */

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
function captureFields(...names) {
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
function fieldChecked(data, name) {
  const value = data?.[name];
  return value === true || value === 'on' || value === 'true';
}

/** Erklärt in einem Satz, wie stark die PIN auf diesem Gerät ist. */
function pinStrengthNote() {
  return state.unlock.keyring
    ? `Der Schlüssel entsteht aus deiner PIN <em>und</em> einem Zufallswert im
       Schlüsselbund des Systems. Ein Angreifer bräuchte beides: die PIN und
       deine angemeldete Sitzung.`
    : `<strong>Auf diesem Gerät ist kein Schlüsselbund erreichbar.</strong>
       Dann hängt alles allein an der PIN — wähle sie entsprechend lang.`;
}

/** Legt die PIN des Programms fest. Muss vor jeder Freigabe geschehen. */
async function createAppPin() {
  const fields = captureFields('pin', 'pin2');

  const res = await dialog({
    title: 'PIN festlegen',
    content: `<p>Diese PIN gilt für das ganze Programm. Bei jeder Datenbank
      entscheidest du danach einzeln, ob sie damit geöffnet werden darf.</p>
      <p>${pinStrengthNote()}</p>
      <p>Nach fünf Fehlversuchen wird die PIN verworfen. Eine Wiederherstellung
      gibt es nicht — dann geht es mit den Master-Passwörtern weiter.</p>
      <label class="field-label">Neue PIN</label>
      ${passwordField('pin', 'Mindestens vier Zeichen', { minlength: 4 })}
      <label class="field-label">Wiederholen</label>
      ${passwordField('pin2', 'PIN wiederholen', { minlength: 4 })}`,
    confirmText: 'Festlegen',
    cancelText: 'Abbrechen',
    onInsert: fields.onInsert
  });

  if (!res?.submit) return false;
  const pin = fields.value('pin', res.data);
  const pin2 = fields.value('pin2', res.data);

  if (!pin) { banner('Bitte eine PIN eingeben.', 'warning'); return false; }
  if (pin !== pin2) { banner('Die beiden PINs stimmen nicht überein.', 'warning'); return false; }

  try {
    await vault.createPin(pin);
    state.unlock = await unlockMethods(settings.get('database.current', null));
    banner('PIN festgelegt.', 'success');
    return true;
  } catch (err) {
    banner(err.message, 'error', 6000);
    return false;
  }
}

/**
 * Schaltet die **offene** Datenbank für PIN und Fingerabdruck frei — oder
 * nimmt die Freigabe zurück. Jede Option wird erklärt.
 */
async function manageAccess() {
  if (state.locked) { banner('Dafür muss die Datenbank offen sein.', 'warning'); return; }
  if (state.unlock.deviceAvailable) return manageDeviceAccess();

  if (!state.unlock.pinSet && !(await createAppPin())) return;

  const fields = captureFields('pin_confirm');

  const res = await dialog({
    title: 'Diese Datenbank freischalten',
    content: `
      <label class="check">
        <input type="checkbox" name="pin" ${state.unlock.pin ? 'checked' : ''}>
        <strong>Mit PIN öffnen</strong>
      </label>
      <p class="hint">Das Master-Passwort wird verschlüsselt hinterlegt; zum Öffnen
      genügt dann die App-PIN. ${pinStrengthNote()}</p>

      <label class="check">
        <input type="checkbox" name="bio" ${state.unlock.biometric ? 'checked' : ''}
          ${state.unlock.keyring ? '' : 'disabled'}>
        <strong>Mit Fingerabdruck öffnen</strong>
      </label>
      <p class="hint">Der Fingerabdruck ist dabei <em>kein Schlüssel</em>, sondern der
      Nachweis, dass du es bist — der Schutz kommt allein aus dem Schlüsselbund.
      Damit ist dieser Weg schwächer als die PIN, denn ein Angreifer braucht nur
      eines statt zwei. Auf macOS und Windows erzwingt die Hardware die Prüfung,
      unter Linux dieses Programm.
      ${state.unlock.keyring ? '' : '<br><strong>Ohne Schlüsselbund nicht möglich.</strong>'}</p>

      <p>Zum Bestätigen die App-PIN eingeben:</p>
      ${passwordField('pin_confirm', 'App-PIN', { minlength: 4 })}`,
    confirmText: 'Übernehmen',
    cancelText: 'Abbrechen',
    onInsert: fields.onInsert
  });

  if (!res?.submit) return;
  const confirm = fields.value('pin_confirm', res.data);

  if (!confirm) { banner('Ohne PIN lässt sich das nicht bestätigen.', 'warning'); return; }

  try {
    await vault.remember(confirm, fieldChecked(res.data, 'pin'), fieldChecked(res.data, 'bio'));
    state.unlock = await unlockMethods(settings.get('database.current', null));
    renderSettings();
    banner('Freigabe gespeichert.', 'success');
  } catch (err) {
    banner(err.message, 'error', 6000);
  }
}

/**
 * Freigabe auf Geräten mit Geräteschlüssel (Windows Hello).
 *
 * Hier ist die Biometrie der Hauptweg und braucht keine PIN. Die PIN bleibt
 * als Rückfall wählbar; nur für sie wird nachgefragt. Den schwächeren
 * Fingerabdruck-Weg über den Schlüsselbund gibt es daneben nicht — er wäre
 * dasselbe in schlechter.
 */
async function manageDeviceAccess() {
  const u = state.unlock;
  const name = esc(deviceName());

  const res = await dialog({
    title: 'Diese Datenbank freischalten',
    content: `
      <label class="check">
        <input type="checkbox" name="device" ${u.device ? 'checked' : ''}>
        <strong>Mit ${name} öffnen</strong>
      </label>
      <p class="hint">Ersetzt beim Öffnen PIN und Master-Passwort. Das Master-Passwort
      wird mit einem Schlüssel versiegelt, den der Sicherheitschip dieses Geräts erst
      nach der Prüfung durch ${name} herausgibt — eine kopierte Datei nützt ohne dieses
      Gerät nichts. Beim ersten Einrichten fragt Windows unter Umständen zweimal.</p>

      <label class="check">
        <input type="checkbox" name="pin" ${u.pin ? 'checked' : ''}>
        <strong>Mit PIN öffnen</strong>
      </label>
      <p class="hint">Rückfallweg, falls ${name} gerade nicht geht. ${pinStrengthNote()}</p>`,
    confirmText: 'Übernehmen',
    cancelText: 'Abbrechen'
  });

  if (!res?.submit) return;
  const wantDevice = fieldChecked(res.data, 'device');
  const wantPin = fieldChecked(res.data, 'pin');

  try {
    if (wantDevice !== u.device) await vault.rememberDevice(wantDevice);

    if (wantPin !== u.pin) {
      if (wantPin && !u.pinSet && !(await createAppPin())) return;
      const confirm = await askAppPin();
      if (!confirm) { banner('Ohne PIN lässt sich die PIN-Freigabe nicht ändern.', 'warning'); }
      else await vault.remember(confirm, wantPin, false);
    }

    state.unlock = await unlockMethods(settings.get('database.current', null));
    renderSettings();
    banner('Freigabe gespeichert.', 'success');
  } catch (err) {
    state.unlock = await unlockMethods(settings.get('database.current', null));
    renderSettings();
    banner(err.message, 'error', 6000);
  }
}

/** Verwirft die PIN des Programms samt aller Freigaben. */
async function clearAppPin() {
  let confirmed = false;
  try {
    const res = await dialog({
      title: 'PIN entfernen',
      content: `Die PIN und alle Freigaben werden verworfen. Danach öffnest du
        jede Datenbank wieder mit ihrem Master-Passwort.`,
      confirmText: 'Entfernen',
      cancelText: 'Abbrechen'
    });
    confirmed = res?.submit ?? res === true;
  } catch { confirmed = false; }
  if (!confirmed) return;

  await vault.clearPin();
  state.unlock = await unlockMethods(settings.get('database.current', null));
  renderSettings();
  banner('PIN entfernt.', 'success');
}

/** Ändert die PIN. Ohne die alte geht es nicht — Absicht. */
async function changePin() {
  const fields = captureFields('old', 'next', 'next2');

  const res = await dialog({
    title: 'PIN ändern',
    content: `<p>Die freigeschalteten Datenbanken bleiben erhalten — sie werden
      im Hintergrund auf die neue PIN umgeschlüsselt. Du musst also
      <strong>keine</strong> Master-Passwörter erneut eingeben.</p>
      <p>Hast du die bisherige PIN vergessen, hilft nur „Entfernen“ — dann sind
      alle Freigaben weg und jede Datenbank braucht wieder ihr Master-Passwort.</p>
      ${passwordField('old', 'Bisherige PIN', { minlength: 4 })}
      ${passwordField('next', 'Neue PIN', { minlength: 4 })}
      ${passwordField('next2', 'Neue PIN wiederholen', { minlength: 4 })}`,
    confirmText: 'Ändern',
    cancelText: 'Abbrechen',
    onInsert: fields.onInsert
  });

  if (!res?.submit) return;
  const old = fields.value('old', res.data);
  const next = fields.value('next', res.data);

  if (!old || !next) { banner('Bitte beide PINs eingeben.', 'warning'); return; }
  if (next !== fields.value('next2', res.data)) { banner('Die beiden neuen PINs stimmen nicht überein.', 'warning'); return; }

  try {
    await vault.changePin(old, next);
    banner('PIN geändert. Alle Freigaben gelten weiter.', 'success');
  } catch (err) {
    banner(err.message, 'error', 6000);
  }
}

/**
 * Baut ein Passwortfeld mit Auge zum Sichtbarmachen.
 *
 * `userDialog` liefert die Werte über `name`, deshalb muss der Umschalter
 * am `type` drehen und darf das Feld nicht ersetzen.
 */
function passwordField(name, placeholder, { required = true, minlength = 0 } = {}) {
  return `<span class="pw-field">
    <input type="password" name="${name}" placeholder="${placeholder}" autocomplete="new-password"
           ${required ? 'required' : ''} ${minlength ? `minlength="${minlength}"` : ''}>
    <button type="button" class="pw-eye" data-shape="square no-background"
            title="Sichtbar machen" aria-label="Sichtbar machen"><span class="msr">visibility</span></button>
  </span>`;
}

/** Hängt die Augen-Knöpfe an, sobald der Dialog im DOM steht. */
function wirePasswordFields(root = document) {
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

/** Legt eine neue, leere Datenbank an und öffnet sie gleich. */
async function createDatabase() {
  // Erst der Ort — dann weiß der Dialog schon, wohin es geht.
  const path = await pickSavePath('passwoerter.kdbx');
  if (!path) { banner('Es wurde kein Speicherort ausgewählt.', 'info'); return; }

  const fields = captureFields('pw', 'pw2');

  const res = await dialog({
    title: 'Neue Datenbank anlegen',
    content: `<p>Wird angelegt unter:<br><code>${esc(path)}</code></p>
      <p>Das Master-Passwort ist der Hauptschlüssel. Es gibt keine
      Wiederherstellung — ist es weg, sind die Einträge weg.</p>
      ${passwordField('pw', 'Master-Passwort', { minlength: 1 })}
      ${passwordField('pw2', 'Master-Passwort wiederholen', { minlength: 1 })}`,
    confirmText: 'Anlegen',
    cancelText: 'Abbrechen',
    onInsert: fields.onInsert
  });

  if (!res?.submit) return;
  const pw = fields.value('pw', res.data);

  if (!pw) { banner('Ohne Master-Passwort geht es nicht.', 'warning'); return; }
  if (pw !== fields.value('pw2', res.data)) { banner('Die beiden Passwörter stimmen nicht überein.', 'warning'); return; }

  try {
    const info = await vault.create({
      path, password: pw,
      autoLockMinutes: Number(settings.get('unlock.autoLockMinutes', 5)) || 0
    });
    await rememberDatabase({ name: info.name, path: info.path });
    await settings.set('database.current', info.path, { silent: true });

    banner('Datenbank angelegt.', 'success');
    await enterUnlocked();
  } catch (err) {
    banner(`Anlegen fehlgeschlagen: ${err.message}`, 'error', 7000);
  }
}

/** Alles, was nach dem Öffnen zu tun ist. */
async function enterUnlocked() {
  state.locked = false;
  delete document.body.dataset.locked;
  $('#lockscreen').hidden = true;
  $('#btn-add').hidden = false;

  await refreshFromVault();
  await vault.ensurePasskeyFolder();

  renderAll();
  showView(settings.get('ui.startView', 'home'));

  startTicker();
  maybeAutoCheck();
}

/**
 * Läuft gerade ein Entsperrversuch?
 *
 * Der Sperrbildschirm wird währenddessen zwar auf „arbeitet" gestellt, aber
 * das Zahnrad führt in die Einstellungen und von dort zurück — und dabei
 * wird er neu gezeichnet, samt bedienbarer Knöpfe. Ein zweiter Versuch
 * liefe dann parallel zum ersten, und beide schrieben am Ende in denselben
 * Tresor. Deshalb hier ein Riegel, der das Neuzeichnen überdauert.
 */
let unlocking = false;

/**
 * Für den Zuhörer auf `vault-unlocked`: Der eigene Versuch meldet sich gleich
 * selbst zurück, dazwischenfunken soll da niemand.
 */
function unlockBusy() {
  return unlocking;
}

async function unlock({ method = 'password', secret = null, remember = null } = {}) {
  if (unlocking) {
    banner('Es läuft bereits ein Entsperrversuch.', 'info');
    return;
  }

  const path = settings.get('database.current', null);
  if (!path && recentDatabases().length === 0 && isTauri) {
    banner('Bitte zuerst eine Datenbank auswählen.', 'warning');
    return;
  }

  // Argon2 rechnet je nach Datenbank mehrere Sekunden. Ohne Rückmeldung
  // sieht das aus, als sei nichts passiert.
  unlocking = true;
  const busy = markUnlocking(true);

  try {
    const info = await vault.unlock({
      path, method, secret, remember,
      autoLockMinutes: Number(settings.get('unlock.autoLockMinutes', 5)) || 0
    });
    if (info?.path && info?.name) await rememberDatabase({ name: info.name, path: info.path });

    if (info?.cachedAt) {
      const when = new Date(info.cachedAt).toLocaleString('de-DE', { dateStyle: 'medium', timeStyle: 'short' });
      banner(`Die Datei ist gerade nicht erreichbar — geöffnet ist die Offline-Kopie vom ${when}. Speichern geht erst wieder, wenn die Datei da ist.`, 'warning', 10000);
    }
    if (info?.readOnly) {
      banner(`${info.format ?? 'Dieses Format'} kann nur gelesen werden — Änderungen lassen sich nicht speichern.`, 'warning', 8000);
    }
    if (remember) {
      banner(remember.allowDevice
        ? `Datenbank für ${deviceName()} freigeschaltet.`
        : 'Datenbank für die PIN freigeschaltet.', 'success');
    }

    await enterUnlocked();
  } catch (err) {
    // Die Datenbank ist offen, nur die Freigabe ging schief — etwa weil
    // Windows Hello beim Einrichten abgebrochen wurde. Dann trotzdem hinein.
    if (/^Geöffnet, aber/.test(err.message)) {
      banner(err.message, 'warning', 8000);
      await vault.adopt();
      if (path) await rememberDatabase({ name: String(path).split(/[\\/]/).pop(), path });
      await enterUnlocked();
      return;
    }
    busy();
    banner(`Entsperren fehlgeschlagen: ${err.message}`, 'error', 6000);
  } finally {
    unlocking = false;
  }
}

/**
 * Schaltet den Sperrbildschirm auf „arbeitet gerade" und liefert eine
 * Funktion, die das zurücknimmt.
 */
function markUnlocking(on) {
  const card = $('#lock-card');
  card?.toggleAttribute('data-busy', on);
  $$('#lock-card button, #lock-card input').forEach(el => { el.disabled = on; });

  const hint = $('.lock-sub');
  const before = hint?.textContent;
  if (on && hint) hint.textContent = 'Wird entschlüsselt … das dauert einen Moment.';

  return () => {
    card?.removeAttribute('data-busy');
    $$('#lock-card button, #lock-card input').forEach(el => { el.disabled = false; });
    if (hint && before != null) hint.textContent = before;
  };
}

async function lockDatabase() {
  if (vault.hasUnsavedChanges()) await vault.commit();
  await vault.lock();
  stopTicker();
  state.entries = [];
  state.strength.clear();
  state.codes.clear();
  state.pwned.clear();
  state.reused = new Set();
  await showLockscreen('Gesperrt — die Werte wurden aus dem Speicher entfernt.');
  banner('Datenbank gesperrt.', 'info');
}

/* =========================================================
   Takt
   ========================================================= */

let tickHandle = null;
function startTicker() {
  stopTicker();
  tickHandle = setInterval(tickTotp, 1000);
  tickTotp();
}
function stopTicker() {
  if (tickHandle) clearInterval(tickHandle);
  tickHandle = null;
}

/* =========================================================
   Automatische Prüfung
   ========================================================= */

const CHECK_INTERVALS = { daily: 86_400_000, weekly: 604_800_000 };

function maybeAutoCheck() {
  const mode = settings.get('checks.automatic', 'weekly');
  if (mode === 'off') return;

  const last = settings.get('checks.lastRunAt', null);
  const due = !last || (Date.now() - last) > (CHECK_INTERVALS[mode] ?? CHECK_INTERVALS.weekly);
  if (due) runSecurityCheck({ silent: true });
}

function bindStaticEvents() {
  $('#search').addEventListener('input', e => {
    state.search = e.target.value.trim().toLowerCase();
    renderPasswords();
  });

  $$('.app-nav button[data-view]').forEach(btn =>
    btn.addEventListener('click', () => {
      // Die Navigation zeigt immer alles — der Filter kommt nur von den Kacheln.
      state.kindFilter = null;
      showView(btn.dataset.view);
    }));

  $('#btn-lock').addEventListener('click', lockDatabase);
  $('#btn-close-settings').addEventListener('click', closeSettingsPage);

  // Rechtsklick irgendwo in der Passwortansicht: es gibt immer ein Menü
  $('#view-passwords').addEventListener('contextmenu', ev => {
    if (ev.target.closest('input, textarea, select')) return;
    if (ev.target.closest('tr[data-id], details.folder > summary')) return;   // haben eigene Menüs
    ev.preventDefault();
    showContextMenu(ev.clientX, ev.clientY, {});
  });

  document.addEventListener('click', ev => {
    if (!ev.target.closest('.context-menu, [data-menu]')) closeContextMenu();
  });
  document.addEventListener('keydown', ev => { if (ev.key === 'Escape') closeContextMenu(); });
  window.addEventListener('scroll', closeContextMenu, true);
  $('#btn-add').addEventListener('click', startCreation);

  let settingsTimer = null;
  settings.onSettingsChange(() => {
    clearTimeout(settingsTimer);
    settingsTimer = setTimeout(() => {
      if (state.locked) { renderLockscreen(); return; }
      renderHome();
      renderPasswords();
      renderSecurity();
      updateSettingsPreview();
    }, 120);
  });
}

/* =========================================================
   Navigation
   ========================================================= */
function showView(name) {
  // Bei gesperrter Datenbank gibt es nur eine sinnvolle Ansicht: die
  // Einstellungen, aufgerufen über das Zahnrad am Sperrbildschirm.
  if (state.locked && !document.body.dataset.settingsOnly) return;
  state.view = name;

  $$('.view').forEach(v => v.toggleAttribute('data-active', v.id === `view-${name}`));

  $$('.app-nav button[data-view]').forEach(b => {
    if (b.classList.contains('brand')) return;
    if (b.dataset.view === name) b.setAttribute('aria-current', 'page');
    else b.removeAttribute('aria-current');
  });

  // Suche und Tag-Leiste stecken im Abschnitt der Passwortliste und
  // verschwinden dadurch von selbst, sobald eine andere Ansicht aktiv ist.
  const isPasswords = name === 'passwords';

  $('#btn-add').hidden = name === 'settings' || name === 'security';

  $('#app-title').textContent = VIEW_TITLES[name] ?? 'WKeePass';

  if (isPasswords) { renderTags(); renderPasswords(); }
  if (name === 'security') renderSecurity();
  if (name === 'settings') renderSettings();
  if (name === 'totp') renderTotp();
}

/* =========================================================
   Filter
   ========================================================= */
function visibleEntries() {
  return state.entries.filter(e => {
    if (state.kindFilter === 'passkey' && !e.passkey) return false;
    if (state.kindFilter === 'files' && !hasFiles(e)) return false;
    if (state.tag && !(e.tags ?? []).includes(state.tag)) return false;
    if (state.search) {
      const hay = `${e.name} ${e.username} ${e.url} ${(e.tags ?? []).join(' ')}`.toLowerCase();
      if (!hay.includes(state.search)) return false;
    }
    return true;
  });
}

/* =========================================================
   Ablaufdatum
   ========================================================= */
function expiryState(entry) {
  if (!true || !entry.expires) return null;
  const days = Math.ceil((new Date(entry.expires).setHours(23, 59, 59) - Date.now()) / 86_400_000);
  if (days < 0) return { kind: 'expired', days };
  const warnDays = settings.forDatabase(settings.get('database.current', null)).expiryWarnDays ?? 14;
  if (days <= warnDays) return { kind: 'expiring', days };
  return null;
}

/* =========================================================
   Rendering
   ========================================================= */
let renderingAll = false;
function renderAll({ includeSettings = true } = {}) {
  if (renderingAll || state.locked) return;
  renderingAll = true;
  try {
    renderTags();
    renderHome();
    renderPasswords();
    renderTotp();
    renderSecurity();
    if (includeSettings) renderSettings();
  } finally {
    renderingAll = false;
  }
}

function renderTags() {
  const tags = vault.allTags();
  const bar = $('#tagbar');

  if (!tags.length) { bar.innerHTML = ''; return; }

  bar.innerHTML = tags
    .map(t => `<button class="tag" data-tag="${esc(t)}" aria-pressed="${state.tag === t}">${esc(t)}</button>`)
    .join('');

  bar.querySelectorAll('.tag').forEach(btn => btn.addEventListener('click', () => {
    // Nochmaliger Klick auf den aktiven Tag hebt den Filter auf
    state.tag = state.tag === btn.dataset.tag ? null : btn.dataset.tag;
    renderTags();
    renderPasswords();
  }));
}

function renderHome() {
  const pwCheck = settings.get('checks.passwordBreach', true);
  const mailCheck = settings.get('checks.emailBreach', true);
  const problems = countProblems();

  const einträge = n => `${n} ${n === 1 ? 'Eintrag' : 'Einträge'}`;

  const tiles = [
    { view: 'passwords', icon: 'key', name: 'Passwörter', count: einträge(state.entries.length) },
    { view: 'passwords', icon: 'passkey', name: 'Passkeys', count: einträge(state.entries.filter(e => e.passkey).length), kind: 'passkey' },
    { view: 'totp', icon: 'timer', name: 'TOTP-Codes', count: `${state.entries.filter(e => e.hasTotp).length} Codes` },
    { view: 'passwords', icon: 'folder_zip', name: 'Dateien', count: einträge(state.entries.filter(hasFiles).length), kind: 'files' }
  ];

  if (pwCheck || mailCheck) {
    tiles.push({
      view: 'security', icon: 'gpp_maybe', name: 'Sicherheitscheck',
      count: state.lastCheck ? `${problems} Funde` : 'noch nicht geprüft',
      variant: problems > 0 ? 'alert' : null
    });
  }

  $('#tile-grid').innerHTML = tiles.map(t => `
    <button class="tile" data-view="${t.view}" ${t.kind ? `data-kind="${t.kind}"` : ''} ${t.variant ? `data-variant="${t.variant}"` : ''}>
      <span class="msr">${t.icon}</span>
      <span class="tile-name">${t.name}</span>
      <span class="tile-count">${t.count}</span>
    </button>`).join('');

  $$('#tile-grid .tile').forEach(btn => btn.addEventListener('click', () => {
    state.kindFilter = btn.dataset.kind ?? null;
    showView(btn.dataset.view);
  }));

  const usage = usageMap();
  const lastUsed = e => Math.max(usage[e.id]?.at ?? 0, Date.parse(e.accessed ?? '') || 0);

  const recent = state.entries
    .filter(e => !e.recycled)
    .sort((a, b) => lastUsed(b) - lastUsed(a))
    .slice(0, 6);
  renderEntryTable($('#recent-list'), recent, { variant: 'compact' });
}

/* =========================================================
   Zuletzt genutzt
   ---------------------------------------------------------
   KeePass führt dafür „LastAccessTime" in der Datei — die zu setzen hieße
   aber, bei jedem Kopieren die ganze Datenbank neu zu schreiben, und das
   bei einer Datei, die über Nextcloud auch KeePassXC anfasst. Deshalb
   merkt sich das Programm die Nutzung selbst, pro Datenbank in
   settings.json, und nimmt den Wert aus der Datei nur dazu.

   Als genutzt zählt: Eintrag öffnen, Benutzername/Passwort/TOTP kopieren,
   Anhang ansehen und jede erlaubte Abfrage über die Browser-Erweiterung
   (der Kern meldet sie mit `entries-used`).

   Gespeichert wird je Eintrag
     at     der letzte Zeitpunkt — bleibt, auch wenn er älter als 7 Tage ist
     week   alle Zeitpunkte der letzten 7 Tage, für die Statistik
   In settings.json stehen dabei nur UUIDs und Zeitpunkte, keine Namen.
   ========================================================= */

/** So viele Einträge behalten ihren letzten Zeitpunkt auch ohne Nutzung in der Woche. */
const USED_LIMIT = 30;
const USAGE_WINDOW = 7 * 24 * 60 * 60 * 1000;

/** Nutzung der offenen Datenbank: `{ [uuid]: { at, week: [ms…] } }`, bereinigt. */
function usageMap(now = Date.now()) {
  const stored = settings.forDatabase(settings.get('database.current', null));
  const map = {};

  // Ältere Fassung: nur eine Liste mit dem letzten Zeitpunkt.
  for (const u of stored.usedEntries ?? []) map[u.id] = { at: u.at, week: [u.at] };
  for (const [id, u] of Object.entries(stored.usage ?? {})) map[id] = { at: u.at ?? 0, week: [...(u.week ?? [])] };

  const newest = new Set(Object.entries(map)
    .sort(([, a], [, b]) => b.at - a.at)
    .slice(0, USED_LIMIT)
    .map(([id]) => id));

  for (const [id, u] of Object.entries(map)) {
    u.week = u.week.filter(t => now - t < USAGE_WINDOW);
    if (!u.week.length && !newest.has(id)) delete map[id];
  }
  return map;
}

/** Wie oft ein Eintrag in den letzten 7 Tagen genutzt wurde. */
function usesThisWeek(id) {
  return usageMap()[id]?.week.length ?? 0;
}

/** Vermerkt, dass Einträge gerade benutzt wurden — eine UUID oder mehrere. */
function markUsed(ids) {
  const path = settings.get('database.current', null);
  const list = [ids].flat().filter(Boolean);
  if (!list.length || !path) return;

  const now = Date.now();
  const map = usageMap(now);
  for (const id of list) {
    const u = map[id] ??= { at: 0, week: [] };
    u.at = now;
    u.week.push(now);
  }

  // Still speichern: Die Liste soll kein Neuzeichnen aller Ansichten auslösen.
  settings.setForDatabase(path, 'usage', map, { silent: true });
  if (!state.locked) renderHome();
}

/** Trägt der Eintrag Anhänge? */
function hasFiles(entry) {
  return !entry.recycled && (entry.attachments ?? []).length > 0;
}

/**
 * Ist das eine reine Dateiablage — nur Name und Anhänge?
 *
 * Solche Einträge öffnen sich als Dateiliste statt als Passwortformular.
 * Notizen und Tags zählen nicht dagegen; sobald Benutzername, URL,
 * Passwort, TOTP oder Passkey dazukommen, ist es ein normaler Eintrag.
 */
function isFileEntry(entry) {
  return (entry.attachments ?? []).length > 0 &&
    !entry.username && !entry.url && !entry.hasPassword && !entry.hasTotp && !entry.passkey;
}

function countProblems() {
  let n = 0;
  for (const e of state.entries) {
    if (state.pwned.get(e.id)?.found) n++;
    if (state.reused.has(e.id)) n++;
    if (expiryState(e)) n++;
  }
  return n + state.emailFindings.reduce((a, f) => a + f.breaches.length, 0);
}

/* ---------- Eintrags-Zeile ---------- */
function wireEntryRows(root) {
  root.querySelectorAll('[data-open]').forEach(el =>
    el.addEventListener('click', () => openEntryDialog(el.dataset.open)));

  // In der Tabelle öffnet ein Klick auf die Zeile den Eintrag —
  // außer man trifft einen der Knöpfe oder Marker.
  // Erst die Auswahl: Sie entscheidet mit, ob ein Klick öffnen darf.
  pick.wireSelection(root, id => vault.getEntry(id)?.folder ?? '');

  root.querySelectorAll('tr[data-id]').forEach(row => {
    row.addEventListener('click', ev => {
      if (ev.target.closest('button, .marker')) return;
      if (pick.selectionActive()) return;
      openEntryDialog(row.dataset.id);
    });

    row.addEventListener('contextmenu', ev => {
      ev.preventDefault();
      ev.stopPropagation();
      showContextMenu(ev.clientX, ev.clientY, { entryId: row.dataset.id });
    });
  });

  root.querySelectorAll('[data-menu]').forEach(btn =>
    btn.addEventListener('click', ev => {
      ev.stopPropagation();
      const r = btn.getBoundingClientRect();
      showContextMenu(r.right - 200, r.bottom + 4, { entryId: btn.dataset.menu });
    }));

  root.querySelectorAll('[data-copy-user]').forEach(el =>
    el.addEventListener('click', () => {
      markUsed(el.dataset.copyUser);
      copyPlain(byId(el.dataset.copyUser).username, 'Benutzername kopiert');
    }));

  // Passwort und TOTP wandern direkt aus dem Kern in die Zwischenablage —
  // die Oberfläche bekommt den Wert nicht zu sehen.
  root.querySelectorAll('[data-copy-pw]').forEach(el =>
    el.addEventListener('click', async () => {
      markUsed(el.dataset.copyPw);
      const ok = await vault.copySecret(byId(el.dataset.copyPw).passwordToken);
      banner(ok ? 'Passwort kopiert' : 'Kopieren nicht möglich.', ok ? 'success' : 'error', 1800);
      if (ok) scheduleClipboardClear();
    }));

  root.querySelectorAll('[data-totp]').forEach(el =>
    el.addEventListener('click', async () => {
      const code = state.codes.get(el.dataset.totp)?.code;
      if (code) markUsed(el.dataset.totp);
      if (code) copyPlain(code, 'TOTP kopiert');
    }));
}

function byId(id) { return state.entries.find(e => e.id === id); }

/* =========================================================
   Kontextmenü einer Zeile
   ---------------------------------------------------------
   Rechtsklick auf dem Rechner, die drei Punkte auf dem Handy.
   ========================================================= */

let openMenu = null;

function closeContextMenu() {
  openMenu?.remove();
  openMenu = null;
}

/**
 * Baut das Kontextmenü passend zu dem, worauf geklickt wurde.
 * „Eintrag erstellen“ und „Ordner erstellen“ sind immer dabei; je nach
 * Ziel kommen die Aktionen für Eintrag oder Ordner davor.
 */
function showContextMenu(x, y, { entryId = null, folderPath = null } = {}) {
  closeContextMenu();

  const entry = entryId ? byId(entryId) : null;
  const folder = folderPath ?? entry?.folder ?? '';
  const items = [];

  // Im Papierkorb gibt es nur zwei sinnvolle Wege: zurück oder endgültig weg.
  const inBin = entry?.recycled || isRecycledFolder(folder);
  if (inBin) {
    if (entry) {
      items.push(
        { action: 'restore', icon: 'restore_from_trash', label: 'Wiederherstellen' },
        { sep: true },
        { action: 'purge', icon: 'delete_forever', label: 'Endgültig löschen', danger: true }
      );
    } else {
      items.push({ action: 'empty-bin', icon: 'delete_forever', label: 'Papierkorb leeren', danger: true });
    }
    return renderContextMenu(items, x, y, { entryId, folderPath, folder });
  }

  if (folderPath !== null) {
    items.push({ action: 'folder-edit', icon: 'drive_file_rename_outline', label: 'Ordner bearbeiten' });
  }

  if (entry) {
    items.push(
      { action: 'edit', icon: 'edit', label: 'Eintrag bearbeiten' },
      { action: 'copy-user', icon: 'person', label: 'Benutzername kopieren', disabled: !entry.username },
      { action: 'copy-pw', icon: 'key', label: 'Passwort kopieren', disabled: !entry.hasPassword },
      { action: 'copy-totp', icon: 'timer', label: 'TOTP kopieren', disabled: !entry.hasTotp },
      { sep: true },
      { action: 'refresh-icon', icon: 'image', label: 'Icon neu laden', disabled: !hostFromUrl(entry.url) },
      { action: 'refresh-title', icon: 'title', label: 'Namen von der Website übernehmen', disabled: !hostFromUrl(entry.url) },
      { sep: true }
    );
  }

  // Immer verfügbar
  items.push(
    { action: 'new-entry', icon: 'edit_note', label: 'Neuer Eintrag' },
    { action: 'new-folder', icon: 'create_new_folder', label: folderPath !== null ? 'Neuer Unterordner' : 'Neuer Ordner' }
  );

  if (entry) items.push({ sep: true }, { action: 'delete', icon: 'delete', label: 'Eintrag löschen', danger: true });
  else if (folderPath) items.push({ sep: true }, { action: 'folder-delete', icon: 'folder_delete', label: 'Ordner löschen', danger: true });

  return renderContextMenu(items, x, y, { entryId, folderPath, folder });
}

/** Liegt dieser Ordner im Papierkorb? */
function isRecycledFolder(path) {
  return path === RECYCLE_BIN || String(path).startsWith(`${RECYCLE_BIN}/`);
}

const RECYCLE_BIN = 'Papierkorb';

function renderContextMenu(items, x, y, { entryId, folderPath, folder }) {
  const menu = document.createElement('div');
  menu.className = 'context-menu';
  menu.innerHTML = items.map(i => i.sep
    ? '<div class="context-sep"></div>'
    : `<button data-action="${i.action}" ${i.disabled ? 'disabled' : ''} ${i.danger ? 'data-danger' : ''}>
         <span class="msr">${i.icon}</span>${i.label}
       </button>`).join('');

  document.body.append(menu);
  openMenu = menu;

  const rect = menu.getBoundingClientRect();
  menu.style.left = `${Math.min(x, window.innerWidth - rect.width - 8)}px`;
  menu.style.top = `${Math.min(y, window.innerHeight - rect.height - 8)}px`;

  menu.querySelectorAll('button[data-action]').forEach(btn =>
    btn.addEventListener('click', async () => {
      const action = btn.dataset.action;
      closeContextMenu();
      await runMenuAction(action, { entryId, folderPath, folder });
    }));
}

async function runMenuAction(action, { entryId, folderPath, folder }) {
  switch (action) {
    case 'new-entry':
      return openEntryDialog(null, folder ? { folder } : {});

    case 'new-folder':
      return openFolderDialog({ parent: folderPath ?? folder ?? '' });

    case 'restore': {
      // Zurück aus dem Papierkorb — nach „Allgemein", weil der ursprüngliche
      // Ordner in KDBX nicht mitgeführt wird.
      await vault.moveEntry(entryId, 'Allgemein');
      await vault.commit();
      await refreshFromVault();
      renderAll({ includeSettings: false });
      banner('Wiederhergestellt.', 'success');
      return;
    }

    case 'purge': {
      // Der Eintrag liegt schon im Papierkorb — löschen heißt hier endgültig.
      await vault.deleteEntry(entryId);
      await vault.commit();
      await refreshFromVault();
      renderAll({ includeSettings: false });
      banner('Endgültig gelöscht.', 'success');
      return;
    }

    case 'empty-bin': {
      const removed = await vault.emptyRecycleBin();
      await vault.commit();
      await refreshFromVault();
      renderAll({ includeSettings: false });
      banner(`${removed} ${removed === 1 ? 'Eintrag' : 'Einträge'} endgültig gelöscht.`, 'success');
      return;
    }

    case 'folder-edit':
      return openFolderDialog({ path: folderPath });

    case 'folder-delete': {
      const res = await dialog({
        title: 'Ordner löschen',
        content: `„${esc(folderPath)}" wird entfernt. Ordner mit Einträgen lassen sich nicht löschen.`,
        confirmText: 'Löschen',
        cancelText: 'Abbrechen'
      });
      if (!(res?.submit ?? res)) return;
      const ok = await vault.removeFolder(folderPath);
      if (!ok) return banner('Der Ordner ist nicht leer.', 'warning');
      return afterStructureChange('Ordner gelöscht.');
    }

    default:
      return runRowAction(action, entryId);
  }
}

async function runRowAction(action, id) {
  const entry = byId(id);
  if (!entry) return;
  if (action.startsWith('copy-')) markUsed(id);

  switch (action) {
    case 'edit':
      return openEntryDialog(id);

    case 'copy-user':
      return copyPlain(entry.username, 'Benutzername kopiert');

    case 'copy-pw': {
      const ok = await vault.copySecret(entry.passwordToken);
      if (ok) { banner('Passwort kopiert', 'success', 1800); scheduleClipboardClear(); }
      return;
    }

    case 'copy-totp': {
      const code = state.codes.get(id)?.code ?? (await vault.totpFor(entry))?.code;
      if (code) copyPlain(code, 'TOTP kopiert');
      return;
    }

    case 'refresh-icon':
      refreshEpoch();
      renderPasswords();
      renderHome();
      return banner('Icon wird neu geladen.', 'info', 2000);

    case 'refresh-title':
      return adoptTitles([entry]);

    case 'delete': {
      const res = await dialog({
        title: 'Eintrag löschen',
        content: `„${esc(entry.name)}" wird aus der Datenbank entfernt. Das lässt sich nicht rückgängig machen.`,
        confirmText: 'Löschen',
        cancelText: 'Abbrechen'
      });
      if (!(res?.submit ?? res)) return;
      await vault.deleteEntry(id);
      return afterStructureChange('Eintrag gelöscht.');
    }
  }
}

/* =========================================================
   Titel von der Website übernehmen
   ========================================================= */

/**
 * Holt den Seitentitel. Im Browser scheitert das an CORS — dort bleibt
 * es beim Hostnamen. In der App holt Rust die Seite ohne diese Sperre.
 */
async function fetchTitle(url) {
  const title = await invokeTitle(url);
  if (title) return title;

  // Rückfallebene: der Hostname ohne www., erster Buchstabe groß
  const host = hostFromUrl(url);
  if (!host) return null;
  const base = host.replace(/^www\./, '').split('.')[0];
  return base.charAt(0).toUpperCase() + base.slice(1);
}

async function invokeTitle(url) {
  try {
    return await invoke('fetch_page_title', { url });
  } catch { return null; }
}

async function adoptTitles(entries) {
  let changed = 0;

  for (const entry of entries) {
    if (!hostFromUrl(entry.url)) continue;
    const title = await fetchTitle(entry.url);
    if (!title || title === entry.name) continue;
    await vault.saveEntry({ ...entry, name: title });
    changed++;
  }

  if (!changed) { banner('Keine Namen geändert.', 'info'); return; }

  await vault.commit();
  await refreshFromVault();
  renderAll({ includeSettings: false });
  banner(`${changed} Name${changed === 1 ? '' : 'n'} übernommen.`, 'success');
}

/* ---------- Passwörter ---------- */

/* =========================================================
   Eintragstabellen
   ---------------------------------------------------------
   Spalten je nach Zusammenhang:
     full     Passwortliste — alles, sortierbar
     compact  Startseite — mit laufendem TOTP-Code als Text
     findings Prüfansicht — ohne TOTP, das spielt dort keine Rolle
   ========================================================= */

const COLUMNS = {
  full:     ['avatar', 'name', 'user', 'url', 'safety', 'totp', 'att', 'modified', 'actions'],
  compact:  ['avatar', 'name', 'user', 'code', 'safety', 'att', 'actions'],
  findings: ['avatar', 'name', 'user', 'url', 'safety', 'att', 'modified', 'actions']
};

const HEADERS = {
  avatar:   { label: '', sort: null },
  name:     { label: 'Name', sort: 't-sort' },
  user:     { label: 'Benutzer', sort: 't-sort' },
  url:      { label: 'URL', sort: 't-sort' },
  folder:   { label: 'Ordner', sort: 't-sort' },
  safety:   { label: '<span class="msr">lock</span>', sort: 't-sort t-type="num"', icon: true, title: 'Zustand des Passworts' },
  totp:     { label: '<span class="msr">timer</span>', sort: 't-sort t-type="num"', icon: true, title: 'TOTP hinterlegt' },
  att:      { label: '<span class="msr">attach_file</span>', sort: 't-sort t-type="num"', icon: true, title: 'Anhang vorhanden' },
  code:     { label: 'Code', sort: null },
  modified: { label: 'Geändert', sort: 't-sort="desc" t-type="date"' },
  actions:  { label: '', sort: null }
};

/**
 * Bewertet einen Eintrag zu einer Ampel.
 *   0 rot    geleakt, sehr schwach oder abgelaufen
 *   1 orange mehrfach genutzt, mittelmäßig oder läuft bald ab
 *   2 grün   unauffällig
 *   3 grau   kein Passwort hinterlegt
 */
function safetyOf(entry) {
  if (!entry.hasPassword) return { level: 'none', sort: 3, title: 'Kein Passwort hinterlegt' };

  const strength = state.strength.get(entry.id);
  const pwned = state.pwned.get(entry.id);
  const exp = expiryState(entry);

  if (pwned?.found) return { level: 'bad', sort: 0, title: `Passwort in ${pwned.count.toLocaleString('de-DE')} Leaks gefunden` };
  if (strength && strength.score < 2) return { level: 'bad', sort: 0, title: `Passwort ${strength.label}` };
  if (exp?.kind === 'expired') return { level: 'bad', sort: 0, title: 'Passwort abgelaufen' };

  if (state.reused.has(entry.id)) return { level: 'warn', sort: 1, title: 'Passwort mehrfach genutzt' };
  if (strength && strength.score === 2) return { level: 'warn', sort: 1, title: `Passwort ${strength.label}` };
  if (exp?.kind === 'expiring') return { level: 'warn', sort: 1, title: `Passwort läuft in ${exp.days} Tagen ab` };

  return { level: 'good', sort: 2, title: strength ? `Passwort ${strength.label}` : 'Unauffällig' };
}

const KIND_FILTERS = {
  passkey: { icon: 'passkey', label: 'Nur Passkeys' },
  files: { icon: 'folder_zip', label: 'Nur Einträge mit Dateien' }
};

function renderLegend() {
  const filter = KIND_FILTERS[state.kindFilter];

  $('#legend').innerHTML = `
    ${filter ? `<button type="button" class="tag kind-filter" id="kind-filter-clear" aria-pressed="true" title="Filter aufheben">
      <span class="msr">${filter.icon}</span>${filter.label}<span class="msr">close</span></button>
      <span class="legend-sep"></span>` : ''}
    Passwort:
    <span class="msr safety" data-level="good">lock</span>Gut
    <span class="msr safety" data-level="warn">lock</span>Achtung
    <span class="msr safety" data-level="bad">lock</span>Problem
    <span class="msr safety" data-level="none">lock</span>keins
    <span class="legend-sep"></span>
    <span class="msr">timer</span>TOTP
    <span class="msr">attach_file</span>Anhang`;

  $('#kind-filter-clear')?.addEventListener('click', () => {
    state.kindFilter = null;
    renderPasswords();
  });
}

function formatDate(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleDateString('de-DE');
}

/** Eine einzelne Zelle. */
function cellHtml(col, e, { iconsOn }) {
  const hasFiles = (e.attachments ?? []).length > 0;

  switch (col) {
    case 'avatar':
      return `<td data-col="avatar">${avatarMarkup(e, { enabled: iconsOn })}</td>`;

    case 'name':
      return `<td data-col="name"><span class="cell-name">${esc(e.name)}</span>${
        e.passkey ? '<span class="badge" data-kind="passkey">Passkey</span>' : ''}</td>`;

    case 'user':
      return `<td data-col="user">${esc(e.username || '—')}</td>`;

    case 'url':
      return `<td data-col="url">${esc(e.url || '—')}</td>`;

    case 'folder':
      return `<td data-col="folder">${esc(e.folder)}</td>`;

    case 'safety': {
      const s = safetyOf(e);
      // data-sort-value: nur so findet tableview den Wert (dataset.sortValue)
      return `<td data-col="safety" data-sort-value="${s.sort}">
        <span class="msr safety" data-level="${s.level}" title="${esc(s.title)}">lock</span></td>`;
    }

    case 'totp':
      return `<td data-col="totp" data-sort-value="${e.hasTotp ? 1 : 0}">${
        e.hasTotp ? `<span class="msr marker" title="TOTP hinterlegt">timer</span>` : ''}</td>`;

    case 'att':
      return `<td data-col="att" data-sort-value="${hasFiles ? 1 : 0}">${
        hasFiles ? `<span class="msr marker" title="${(e.attachments ?? []).length} Anhang/Anhänge">attach_file</span>` : ''}</td>`;

    case 'code':
      return `<td data-col="code">${
        e.hasTotp ? `<span class="totp-inline" data-totp="${e.id}">······</span>` : ''}</td>`;

    case 'modified':
      return `<td data-col="modified" data-sort-value="${esc(e.modified ?? '')}">${formatDate(e.modified)}</td>`;

    case 'actions':
      return `<td data-col="actions">
        <div class="row-actions">
          <button class="button" data-shape="square" data-copy-user="${e.id}"
                  title="Benutzername kopieren" ${e.username ? '' : 'disabled'}><span class="msr">person</span></button>
          <button class="button" data-shape="square" data-copy-pw="${e.id}"
                  title="Passwort kopieren" ${e.hasPassword ? '' : 'disabled'}><span class="msr">key</span></button>
          <button class="button" data-shape="square" data-menu="${e.id}" title="Mehr"><span class="msr">more_vert</span></button>
        </div></td>`;

    default:
      return '';
  }
}

function entryRowHtml(e, cols, opts) {
  const box = pick.selectionActive()
    ? `<td class="pick-cell"><span class="pick-box ${pick.isSelected(e.id) ? 'on' : ''}"><span class="msr">${
        pick.isSelected(e.id) ? 'check_box' : 'check_box_outline_blank'}</span></span></td>`
    : '';

  // Gelöschte bleiben sichtbar, werden aber als das kenntlich gemacht,
  // was sie sind — und bei den Auswertungen ausgelassen.
  const recycled = e.recycled ? ' data-recycled title="Liegt im Papierkorb"' : '';
  return `<tr data-id="${e.id}" data-drag-id="entry:${e.id}" data-drag-label="${esc(e.name)}"${recycled}>${box}${cols.map(c => cellHtml(c, e, opts)).join('')}</tr>`;
}

function headerHtml(cols, sortable) {
  const box = pick.selectionActive() ? '<th class="pick-cell"></th>' : '';
  return box + cols.map(col => {
    const h = HEADERS[col] ?? { label: '' };
    const attrs = sortable && h.sort ? h.sort : '';
    return `<th data-col="${col}" ${attrs} ${h.icon ? 'data-icon-head' : ''} ${h.title ? `title="${h.title}"` : ''}>${h.label}</th>`;
  }).join('');
}

/**
 * Baut eine Tabelle.
 * @param {{variant?: string, sortable?: boolean, search?: boolean}} options
 */
function tableHtml(list, { variant = 'full', sortable = false, search = false } = {}) {
  const cols = COLUMNS[variant] ?? COLUMNS.full;
  const iconsOn = settings.get('icons.download', true);

  return `
    <div class="table-scroll">
      <table class="entry-table" data-variant="${variant}" ${search ? 't-search' : ''}>
        <thead><tr>${headerHtml(cols, sortable)}</tr></thead>
        <tbody>${list.map(e => entryRowHtml(e, cols, { iconsOn })).join('')}</tbody>
      </table>
    </div>`;
}

function renderEntryTable(host, list, options = {}) {
  if (!list.length) {
    host.innerHTML = `<p class="empty-state">Keine Einträge.</p>`;
    return;
  }
  host.innerHTML = tableHtml(list, options);
  wireEntryRows(host);
  if (options.sortable) ensureTableview();
  tickTotp();
}

/* ---------- Ordnerbaum ---------- */

/** Baut aus den Ordnerpfaden einen Baum mit den zugehörigen Einträgen. */
function folderTree(list) {
  const root = { name: '', path: '', children: new Map(), entries: [] };

  for (const e of list) {
    const parts = String(e.folder || 'Allgemein').split('/').map(p => p.trim()).filter(Boolean);
    let node = root;
    for (const part of parts) {
      if (!node.children.has(part)) {
        node.children.set(part, {
          name: part,
          path: node.path ? `${node.path}/${part}` : part,
          children: new Map(),
          entries: []
        });
      }
      node = node.children.get(part);
    }
    node.entries.push(e);
  }
  return root;
}

/** Zählt Einträge inklusive Unterordnern — für die Anzeige am Ordner. */
function countDeep(node) {
  let n = node.entries.length;
  for (const child of node.children.values()) n += countDeep(child);
  return n;
}

function folderHtml(node, depth = 0) {
  // Standard: zu. Geöffnet ist nur, was der Nutzer aufgeklappt hat.
  const open = state.expanded.has(node.path);

  const inner = [
    ...[...node.children.values()]
      .sort((a, b) => a.name.localeCompare(b.name, 'de'))
      .map(child => folderHtml(child, depth + 1)),
    node.entries.length ? tableHtml(node.entries, { sortable: true, search: true }) : ''
  ].join('');

  return `
    <details class="folder" data-folder="${esc(node.path)}" data-depth="${depth}" ${open ? 'open' : ''}>
      <summary data-drag-id="folder:${esc(node.path)}" data-drag-label="${esc(node.name)}" data-drop-path="${esc(node.path)}">
        <span class="msr folder-icon">folder</span>
        <span class="folder-name">${esc(node.name)}</span>
        <span class="folder-count">${countDeep(node)}</span>
      </summary>
      <div class="folder-body">${inner}</div>
    </details>`;
}

function renderPasswords() {
  renderLegend();
  const host = $('#entry-table');
  const list = visibleEntries();

  if (!list.length) {
    host.innerHTML = `<p class="empty-state">Keine Einträge gefunden.</p>`;
    return;
  }

  // Bei aktiver Suche fallen die Ordner weg — eine flache Liste über alles.
  if (state.search) {
    host.innerHTML = tableHtml(list, { variant: 'full', sortable: true });
    host.querySelector('.entry-table')?.insertAdjacentHTML('afterbegin', '');
    wireEntryRows(host);
    ensureTableview();
    return;
  }

  const tree = folderTree(list);
  host.innerHTML = [...tree.children.values()]
    .sort((a, b) => a.name.localeCompare(b.name, 'de'))
    .map(child => folderHtml(child))
    .join('') + (tree.entries.length ? tableHtml(tree.entries, { sortable: true, search: true }) : '');

  host.querySelectorAll('details.folder > summary').forEach(sum => {
    sum.addEventListener('click', () => {
      const d = sum.parentElement;
      const f = d.dataset.folder;
      // Der Klick kommt vor dem Umschalten: d.open ist noch der alte Zustand.
      if (d.open) state.expanded.delete(f); else state.expanded.add(f);
      persistExpanded();
    });

    // Doppelklick öffnet den Ordner-Dialog; das doppelte Umschalten
    // durch die beiden Klicks hebt sich auf, der Zustand bleibt.
    sum.addEventListener('dblclick', ev => {
      ev.preventDefault();
      openFolderDialog({ path: sum.parentElement.dataset.folder });
    });

    sum.addEventListener('contextmenu', ev => {
      ev.preventDefault();
      ev.stopPropagation();
      showContextMenu(ev.clientX, ev.clientY, { folderPath: sum.parentElement.dataset.folder });
    });
  });

  wireEntryRows(host);
  setupDragMove(host);
  ensureTableview();
}

/** Rüstet die eben gebauten Tabellen mit Sortierung aus. */
function ensureTableview() {
  return tableview();
}

/* ---------- TOTP ---------- */
const PREVIEW_SECONDS = 10;   // ab hier den kommenden Code klein einblenden

function renderTotp() {
  const list = state.entries.filter(e => e.hasTotp);
  const host = $('#totp-list');

  if (!list.length) {
    host.innerHTML = `<p class="empty-state">Keine TOTP-Einträge vorhanden.</p>`;
    return;
  }

  host.innerHTML = list.map(e => `
    <div class="totp-card" data-totp-card="${e.id}" title="Klick kopiert, Doppelklick öffnet den Eintrag">
      <div class="totp-ring">
        <svg viewBox="0 0 36 36">
          <circle class="track" cx="18" cy="18" r="15"></circle>
          <circle class="progress" cx="18" cy="18" r="15" data-ring="${e.id}"></circle>
        </svg>
        <span class="totp-seconds" data-sec="${e.id}"></span>
      </div>
      <div class="totp-body">
        <div class="totp-name">${esc(e.name)}</div>
        <div class="totp-issuer">${esc(e.url || e.username || '—')}</div>
      </div>
      <div class="totp-values">
        <div class="totp-value" data-code="${e.id}">······</div>
        <div class="totp-next" data-next="${e.id}" hidden></div>
      </div>
    </div>`).join('');

  // Einfacher Klick kopiert, Doppelklick öffnet — der Einzelklick wartet
  // kurz ab, damit er einen Doppelklick nicht vorwegnimmt.
  host.querySelectorAll('[data-totp-card]').forEach(card => {
    let timer = null;

    card.addEventListener('click', () => {
      if (timer) return;
      timer = setTimeout(() => {
        timer = null;
        const code = state.codes.get(card.dataset.totpCard)?.code;
        if (code) markUsed(card.dataset.totpCard);
        if (code) copyPlain(code, 'Code kopiert');
      }, 220);
    });

    card.addEventListener('dblclick', () => {
      clearTimeout(timer);
      timer = null;
      openEntryDialog(card.dataset.totpCard);
    });
  });

  tickTotp();
}

let ticking = false;
async function tickTotp() {
  if (ticking || state.locked) return;
  ticking = true;
  try { await tickTotpInner(); } finally { ticking = false; }
}

async function tickTotpInner() {
  const circ = 2 * Math.PI * 15;

  for (const e of state.entries) {
    if (!e.hasTotp) continue;

    const result = await vault.totpFor(e);
    if (!result) continue;

    state.codes.set(e.id, result);

    const period = e.totpConfig?.period || 30;
    $$(`[data-code="${e.id}"]`).forEach(el => el.textContent = result.code);
    $$(`[data-totp="${e.id}"]`).forEach(el => el.textContent = result.code);
    $$(`[data-sec="${e.id}"]`).forEach(el => el.textContent = result.remaining);
    $$(`[data-ring="${e.id}"]`).forEach(el => {
      el.setAttribute('stroke-dasharray', circ);
      el.setAttribute('stroke-dashoffset', circ * (1 - result.remaining / period));
      el.classList.toggle('ending', result.remaining <= PREVIEW_SECONDS);
    });

    // Kurz vor Ablauf schon den nächsten Code zeigen
    const nextNodes = $$(`[data-next="${e.id}"]`);
    if (nextNodes.length) {
      if (result.remaining <= PREVIEW_SECONDS) {
        const upcoming = await vault.totpFor(e, { at: Date.now() + (result.remaining + 1) * 1000 });
        nextNodes.forEach(el => {
          el.textContent = `als Nächstes ${upcoming?.code ?? '······'}`;
          el.hidden = false;
        });
      } else {
        nextNodes.forEach(el => { el.hidden = true; });
      }
    }
  }
}

/* =========================================================
   Sicherheitscheck
   ========================================================= */
function renderSecurity() {
  const pwCheck = settings.get('checks.passwordBreach', true);
  const mailCheck = settings.get('checks.emailBreach', true);

  const live = liveEntries();
  const leaked = live.filter(e => state.pwned.get(e.id)?.found);
  const weak = settings.get('checks.passwordStrength', true)
    ? live.filter(e => (state.strength.get(e.id)?.score ?? 9) < 2)
    : [];
  const reused = live.filter(e => state.reused.has(e.id));
  const expiring = live.filter(e => expiryState(e));
  const mailCount = state.emailFindings.reduce((a, f) => a + f.breaches.length, 0);

  const stats = [
    { key: 'leaked', num: pwCheck ? leaked.length : '–', label: 'geleakte Passwörter', tone: leaked.length ? 'bad' : 'ok' },
    { key: 'weak', num: weak.length, label: 'schwache Passwörter', tone: weak.length ? 'warn' : 'ok' },
    { key: 'reused', num: reused.length, label: 'mehrfach genutzt', tone: reused.length ? 'warn' : 'ok' },
    { key: 'expiring', num: expiring.length, label: 'abgelaufen / bald fällig', tone: expiring.length ? 'warn' : 'ok' },
    { key: 'mail', num: mailCheck ? mailCount : '–', label: 'E-Mail-Leaks', tone: mailCount ? 'bad' : 'ok' }
  ];

  const last = settings.get('checks.lastRunAt', null);

  const findings = e => {
    const s = state.strength.get(e.id);
    const p = state.pwned.get(e.id);
    const x = expiryState(e);
    const parts = [];
    if (p?.found) parts.push(`${p.count.toLocaleString('de-DE')}× in Leaks`);
    if (s && s.score < 2) parts.push(`Stärke: ${s.label}`);
    if (state.reused.has(e.id)) parts.push('mehrfach genutzt');
    if (x?.kind === 'expired') parts.push(`seit ${Math.abs(x.days)} Tagen abgelaufen`);
    if (x?.kind === 'expiring') parts.push(`läuft in ${x.days} Tagen ab`);
    return parts.join(' · ');
  };

  const group = (id, title, items, empty) => `
    <div class="section-label" id="sec-${id}">${title}</div>
    ${items.length
      ? `<div class="findings-table" data-list="${id}"></div>`
      : `<div class="finding" data-tone="ok"><div class="finding-title"><span class="msr">check_circle</span>${empty}</div></div>`}`;

  const groups = [
    pwCheck ? { id: 'leaked', title: 'Geleakte Passwörter', items: leaked, empty: 'Keine Treffer' } : null,
    { id: 'weak', title: 'Schwache Passwörter', items: weak, empty: 'Alle Passwörter ausreichend stark' },
    { id: 'reused', title: 'Mehrfach genutzte Passwörter', items: reused, empty: 'Keine Mehrfachnutzung' },
    { id: 'expiring', title: 'Ablaufdaten', items: expiring, empty: 'Kein Passwort fällig' }
  ].filter(Boolean);

  $('#security-body').innerHTML = `
    <div class="security-layout">
      <aside class="security-stats">
        <div class="security-elements">
          ${stats.map(st => `
          <button class="stat" data-tone="${st.tone}" data-jump="sec-${st.key}">
            <span class="stat-num">${st.num}</span>
            <span class="stat-label">${st.label}</span>
          </button>`).join('')}
        </div>
        <div class="security-check">
          <button class="button hightlight" data-shape="full" id="btn-run-check" ${state.checkRunning ? 'disabled' : ''}>
            <span class="msr">${state.checkRunning ? 'progress_activity' : 'shield_lock'}</span>
            ${state.checkRunning ? 'Prüfe …' : 'Jetzt prüfen'}
          </button>
          <p class="security-last">${last ? `Zuletzt: ${new Date(last).toLocaleString('de-DE')}` : 'Noch nicht geprüft'}</p>
        </div>
      </aside>

      <div class="security-findings">
        ${groups.map(g => group(g.id, g.title, g.items, g.empty)).join('')}
        ${mailCheck ? `
          <div class="section-label" id="sec-mail">E-Mail-Datenlecks</div>
          ${state.emailFindings.filter(f => f.breaches.length).length
            ? state.emailFindings.filter(f => f.breaches.length).map(f => `
              <div class="finding" data-tone="bad">
                <div class="finding-title"><span class="msr">mail</span>${esc(f.email)}</div>
                <div class="finding-text">Betroffen von: ${esc(f.breaches.map(b => b.name).join(', '))}</div>
              </div>`).join('')
            : `<div class="finding" data-tone="ok"><div class="finding-title"><span class="msr">check_circle</span>Keine Treffer</div></div>`}` : ''}
      </div>
    </div>`;

  // Befunde in derselben Darstellung wie überall
  for (const g of groups) {
    const box = $(`.findings-table[data-list="${g.id}"]`);
    if (box) renderEntryTable(box, g.items, { variant: 'findings' });
  }

  $('#btn-run-check')?.addEventListener('click', () => runSecurityCheck());

  $$('#security-body [data-jump]').forEach(btn => btn.addEventListener('click', () => {
    document.getElementById(btn.dataset.jump)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }));

  // Direkt aus dem Befund heraus bearbeiten
  $$('#security-body [data-edit]').forEach(btn =>
    btn.addEventListener('click', () => openEntryDialog(btn.dataset.edit)));
}

async function runSecurityCheck({ silent = false } = {}) {
  if (state.checkRunning) return;
  state.checkRunning = true;
  renderSecurity();

  const errors = [];

  if (settings.get('checks.passwordBreach', true)) {
    // Der Kern liefert nur Hashes; nach außen geht davon bloß das Präfix.
    for (const target of await vault.hashTargets()) {
      const r = await checkPwnedByHash(target);
      if (r.error) errors.push(`Passwort-Check: ${r.error}`);
      state.pwned.set(target.id, r);
    }
  } else state.pwned.clear();

  state.reused = settings.get('checks.reuseDetection', true)
    ? await vault.reusedIds() : new Set();

  state.strength = settings.get('checks.passwordStrength', true)
    ? await vault.strengthMap() : new Map();

  if (settings.get('checks.emailBreach', true)) {
    const configured = [];
    const addresses = configured.length ? configured : vault.collectEmails();
    state.emailFindings = [];
    for (const mail of addresses) {
      const r = await checkEmailBreached(mail);
      if (r.error) errors.push(`E-Mail-Check: ${r.error}`);
      state.emailFindings.push(r);
    }
  } else state.emailFindings = [];

  state.lastCheck = Date.now();
  await settings.set('checks.lastRunAt', state.lastCheck, { silent: true });
  state.checkRunning = false;
  renderSecurity();
  renderHome();
  renderPasswords();

  if (!silent) {
    if (errors.length) banner(`Prüfung teilweise fehlgeschlagen: ${[...new Set(errors)][0]}`, 'warning', 6000);
    else {
      const n = countProblems();
      banner(n ? `${n} Funde in der Prüfung.` : 'Keine Probleme gefunden.', n ? 'warning' : 'success');
    }
  }
}

/* =========================================================
   Einstellungen
   ========================================================= */
/**
 * Baut die Einstellungen.
 *
 * Genau eine Quelle für beide Orte: die Einstellungsseite bei offener
 * Datenbank und das Zahnrad auf dem Sperrbildschirm. Der einzige
 * Unterschied ist der Abschnitt „Diese Datenbank" — ohne offene Datenbank
 * gibt es ihn schlicht nicht.
 */
function settingsMarkup() {
  const s = settings.getSettings();
  const theme = s.appearance?.theme ?? 'system';
  const current = recentDatabases().find(d => d.path === s.database?.current);
  const dbSettings = settings.forDatabase(s.database?.current ?? null);

  return `
    <div class="settings-group">
      <div class="section-label">Darstellung</div>
      <div class="settings-card">
        <div class="setting">
          <div class="setting-label"><strong>Farbschema</strong><small>System folgt der Einstellung des Betriebssystems</small></div>
          <div class="setting-control">
            <div class="group-radio" id="theme-switch">
              ${[['light', 'Hell'], ['dark', 'Dunkel'], ['system', 'System']].map(([value, label]) => `
                <label>
                  <input type="radio" name="appearance.theme" value="${value}" ${theme === value ? 'checked' : ''}>${label}
                </label>`).join('')}
            </div>
          </div>
        </div>
        <div class="setting">
          <div class="setting-label"><strong>Akzentfarbe</strong><small>Warn- und Gefahrfarben bleiben unverändert, damit Hinweise erkennbar bleiben</small></div>
          <div class="setting-control">
            <input type="color" id="primary-color" name="appearance.primary" value="${esc(s.appearance?.primary ?? '#2FA69A')}">
          </div>
        </div>
      </div>
    </div>

    <div class="settings-group">
      <div class="section-label">Entsperren</div>
      <div class="settings-card">
        <div class="setting">
          <div class="setting-label">
            <strong>Biometrie verwenden</strong>
            <small>${state.unlock.deviceAvailable
              ? `${esc(deviceName())} — beim Öffnen anbieten, ersetzt PIN und Master-Passwort`
              : state.unlock.biometric ? 'Fingerabdruck oder Gesichtserkennung' : 'Auf diesem Gerät nicht verfügbar'}</small>
          </div>
          <div class="setting-control"><input type="checkbox" data-shape="toggle" data-set="unlock.biometrics" name="unlock.biometrics" ${s.unlock?.biometrics ? 'checked' : ''} ${state.unlock.biometric || state.unlock.deviceAvailable ? '' : 'disabled'}></div>
        </div>
        <div class="setting">
          <div class="setting-label">
            <strong>PIN des Programms</strong>
            <small>${state.unlock.pinSet
              ? (state.unlock.keyring
                  ? 'Festgelegt — geschützt durch PIN und Schlüsselbund'
                  : 'Festgelegt — ohne Schlüsselbund hängt alles an der PIN')
              : 'Noch keine PIN. Gilt für alle Datenbanken.'}</small>
          </div>
          <div class="setting-control">
            ${state.unlock.pinSet
              ? `<button type="button" class="button" id="btn-pin-change">Ändern …</button>
                 <button type="button" class="button" id="btn-pin-clear">Entfernen</button>`
              : '<button type="button" class="button" id="btn-pin-create">Festlegen …</button>'}
          </div>
        </div>
        <div class="setting">
          <div class="setting-label"><strong>Automatisch sperren</strong><small>Minuten ohne Aktivität</small></div>
          <div class="setting-control"><input type="number" min="1" max="120" data-set="unlock.autoLockMinutes" name="unlock.autoLockMinutes" value="${s.unlock?.autoLockMinutes ?? 5}"></div>
        </div>
        <div class="setting">
          <div class="setting-label"><strong>Zwischenablage leeren</strong><small>Sekunden nach dem Kopieren</small></div>
          <div class="setting-control"><input type="number" min="0" max="300" data-set="unlock.clipboardClearSeconds" name="unlock.clipboardClearSeconds" value="${s.unlock?.clipboardClearSeconds ?? 30}"></div>
        </div>
      </div>
    </div>

    <div class="settings-group">
      <div class="section-label">Browser-Erweiterung</div>
      <div class="settings-card" id="browser-card">
        <div class="setting"><div class="setting-label"><small>Wird geladen …</small></div></div>
      </div>
    </div>

    <div class="settings-group">
      <div class="section-label">Website-Icons</div>
      <div class="settings-card">
        <div class="setting">
          <div class="setting-label">
            <strong>Icons der Websites laden</strong>
            <small>Direkt von der jeweiligen Domain, ohne Sammeldienst. Die Domain sieht dabei deine IP-Adresse.</small>
          </div>
          <div class="setting-control"><input type="checkbox" data-shape="toggle" data-set="icons.download" name="icons.download" ${s.icons?.download ? 'checked' : ''}></div>
        </div>
      </div>
    </div>

    <div class="settings-group" data-needs-db>
      <div class="section-label">Diese Datenbank</div>
      <div class="settings-card">
        <div class="setting">
          <div class="setting-label"><strong>${esc(current?.name ?? 'Geöffnete Datenbank')}</strong>
            <small>${esc(current?.path ?? '')}</small></div>
        </div>
        <div class="setting">
          <div class="setting-label"><strong>Automatisch synchronisieren</strong></div>
          <div class="setting-control">
            <input type="checkbox" data-shape="toggle" data-set-db="autoSync" name="db.autoSync" ${dbSettings.autoSync ? 'checked' : ''}>
          </div>
        </div>
        <div class="setting">
          <div class="setting-label"><strong>Warnen vor Ablauf</strong><small>Tage im Voraus</small></div>
          <div class="setting-control">
            <input type="number" min="1" max="180" data-set-db="expiryWarnDays" name="db.expiryWarnDays" value="${dbSettings.expiryWarnDays ?? 14}">
          </div>
        </div>
        <div class="setting">
          <div class="setting-label">
            <strong>Bequem entsperren</strong>
            <small>${[state.unlock.device ? esc(deviceName()) : null, state.unlock.pin ? 'PIN' : null, state.unlock.biometric ? 'Fingerabdruck' : null]
              .filter(Boolean).join(' und ') || 'Nur mit Master-Passwort'}</small>
          </div>
          <div class="setting-control"><button type="button" class="button" id="btn-access">Wählen …</button></div>
        </div>
        <div class="setting">
          <div class="setting-label"><strong>Alle Icons neu abrufen</strong><small>Umgeht den Zwischenspeicher</small></div>
          <div class="setting-control"><button type="button" class="button" id="btn-refresh-icons"><span class="msr">refresh</span>&nbsp;Neu laden</button></div>
        </div>
        <div class="setting">
          <div class="setting-label"><strong>Namen von den Websites übernehmen</strong><small>Setzt bei allen Einträgen mit URL den Seitentitel als Namen</small></div>
          <div class="setting-control"><button type="button" class="button" id="btn-adopt-titles"><span class="msr">title</span>&nbsp;Übernehmen</button></div>
        </div>
        <div class="setting">
          <div class="setting-label"><strong>Papierkorb leeren</strong><small>Entfernt die gelöschten Einträge endgültig</small></div>
          <div class="setting-control"><button type="button" class="button" id="btn-empty-bin">Leeren …</button></div>
        </div>
      </div>
    </div>

    <div class="settings-group">
      <div class="section-label">Prüfungen</div>
      <div class="settings-card">
        <div class="setting">
          <div class="setting-label"><strong>Passwortstärke anzeigen</strong><small>Berechnung läuft im Kern</small></div>
          <div class="setting-control"><input type="checkbox" data-shape="toggle" data-set="checks.passwordStrength" name="checks.passwordStrength" ${s.checks?.passwordStrength ? 'checked' : ''}></div>
        </div>
        <div class="setting">
          <div class="setting-label"><strong>Mehrfachnutzung erkennen</strong><small>Vergleich innerhalb der Datenbank</small></div>
          <div class="setting-control"><input type="checkbox" data-shape="toggle" data-set="checks.reuseDetection" name="checks.reuseDetection" ${s.checks?.reuseDetection ? 'checked' : ''}></div>
        </div>
        <div class="setting">
          <div class="setting-label"><strong>Vorwarnzeit bei Ablauf</strong><small>Tage vor dem Ablaufdatum</small></div>
          <div class="setting-control"><input type="number" min="1" max="180" data-set="checks.expiryWarnDays" name="checks.expiryWarnDays" value="${s.checks?.expiryWarnDays ?? 14}"></div>
        </div>
        <div class="setting">
          <div class="setting-label"><strong>Passwörter auf Leaks prüfen</strong><small>Have I Been Pwned — es wird nur ein Hash-Präfix gesendet, nie das Passwort</small></div>
          <div class="setting-control"><input type="checkbox" data-shape="toggle" data-set="checks.passwordBreach" name="checks.passwordBreach" ${s.checks?.passwordBreach ? 'checked' : ''}></div>
        </div>
        <div class="setting">
          <div class="setting-label"><strong>E-Mail-Adressen prüfen</strong><small>Über XposedOrNot</small></div>
          <div class="setting-control"><input type="checkbox" data-shape="toggle" data-set="checks.emailBreach" name="checks.emailBreach" ${s.checks?.emailBreach ? 'checked' : ''}></div>
        </div>
        <div class="setting">
          <div class="setting-label">
            <strong>Automatisch prüfen</strong>
            <small>Beim Öffnen der App, sofern die letzte Prüfung länger her ist${s.checks?.lastRunAt ? ` — zuletzt am ${new Date(s.checks.lastRunAt).toLocaleDateString('de-DE')}` : ''}</small>
          </div>
          <div class="setting-control">
            <div class="group-radio" id="auto-check">
              ${[['daily', 'Täglich'], ['weekly', 'Wöchentlich'], ['off', 'Aus']].map(([value, label]) => `
                <label>
                  <input type="radio" name="checks.automatic" value="${value}"
                    ${(s.checks?.automatic ?? 'off') === value ? 'checked' : ''}>${label}
                </label>`).join('')}
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="settings-group">
      <div class="section-label">Exportieren und Importieren</div>
      <div class="settings-card">
        <div class="setting">
          <div class="setting-label"><strong>Einstellungen exportieren</strong><small>Als settings.json sichern</small></div>
          <div class="setting-control"><button type="button" class="button" id="btn-export">Exportieren</button></div>
        </div>
        <div class="setting">
          <div class="setting-label"><strong>Einstellungen importieren</strong><small>Aus einer settings.json übernehmen</small></div>
          <div class="setting-control"><button type="button" class="button" id="btn-import">Importieren</button></div>
        </div>
        <div class="setting">
          <div class="setting-label"><strong>Auf Standard zurücksetzen</strong><small>Die Datenbank bleibt unverändert</small></div>
          <div class="setting-control"><button type="button" class="button" id="btn-reset">Zurücksetzen</button></div>
        </div>
      </div>
    </div>

    <div class="settings-group">
      <div class="section-label">Aktuelle Konfiguration</div>
      <div class="settings-card">
        <pre id="settings-preview" style="margin:0;padding:0.85rem;font-size:0.75rem;overflow-x:auto;font-family:var(--font-mono)">${esc(settings.exportSettings())}</pre>
      </div>
    </div>`;
}

function renderSettings() {
  const body = $('#settings-body');
  body.innerHTML = settingsMarkup();
  wireSettings(body);

  // Nachgereicht: Der Zustand kommt aus dem Kern und würde das Zeichnen
  // sonst aufhalten.
  renderBrowserSection();
}

/**
 * Der Abschnitt zur Browser-Anbindung.
 *
 * Zeigt, ob der Kanal steht, wo er liegt, bei welchen Browsern wir
 * eingetragen sind und welche sich verknüpft haben. Der Pfad steht sichtbar
 * da, weil man ihn bei Problemen als Erstes braucht.
 */
async function renderBrowserSection() {
  const card = $('#browser-card');
  if (!card) return;

  let status;
  try {
    status = await vault.browserStatus();
  } catch (err) {
    card.innerHTML = `<div class="setting"><div class="setting-label">
      <strong>Nicht verfügbar</strong><small>${esc(err.message)}</small></div></div>`;
    return;
  }

  const eingerichtet = status.installed.length
    ? status.installed.join(', ')
    : 'Bei keinem Browser eingetragen';

  const verknuepft = status.associations.length
    ? status.associations.map(name => `
        <div class="setting">
          <div class="setting-label"><strong>${esc(name)}</strong><small>verknüpft</small></div>
          <div class="setting-control">
            <button type="button" class="button" data-forget="${esc(name)}">Trennen</button>
          </div>
        </div>`).join('')
    : `<div class="setting"><div class="setting-label">
         <small>Noch kein Browser verknüpft.</small></div></div>`;

  const guard = settings.get('browser.guard', 'identify');

  card.innerHTML = `
    <div class="setting">
      <div class="setting-label">
        <strong>Vor dem Ausfüllen</strong>
        <small>Wie schwer die Antwort wiegt, wenn ein verknüpfter Browser
        Zugangsdaten anfragt. Wird gefragt, dann direkt hintereinander eine
        Minute lang nicht erneut.</small>
      </div>
      <div class="setting-control">
        <div class="group-radio" id="browser-guard">
          ${[['never', 'Nichts'], ['confirm', 'Bestätigen'], ['identify', 'Legitimieren']]
            .map(([value, label]) => `
              <label>
                <input type="radio" name="browser.guard" value="${value}"
                  ${guard === value ? 'checked' : ''}>${label}
              </label>`).join('')}
        </div>
      </div>
    </div>
    <div class="setting">
      <div class="setting-label">
        <strong>Kanal</strong>
        <small>${status.listening ? 'Aktiv' : 'Nicht aktiv'} — <code>${esc(status.socket)}</code></small>
      </div>
    </div>
    <div class="setting">
      <div class="setting-label">
        <strong>Eingetragen bei</strong>
        <small>${esc(eingerichtet)}</small>
      </div>
      <div class="setting-control">
        <button type="button" class="button" id="btn-browser-install">Einrichten</button>
        <button type="button" class="button" id="btn-browser-remove">Entfernen</button>
      </div>
    </div>
    ${verknuepft}`;

  card.querySelectorAll('[name="browser.guard"]').forEach(el =>
    el.addEventListener('change', async () => {
      await settings.set('browser.guard', el.value, { silent: true });
      banner({
        never: 'Verknüpfte Browser füllen ohne Rückfrage aus.',
        confirm: 'Ein Knopfdruck genügt — ohne Nachweis.',
        identify: 'PIN, Master-Passwort oder Fingerabdruck vor dem Ausfüllen.'
      }[el.value], el.value === 'never' ? 'warning' : 'success', 5000);
    }));

  card.querySelector('#btn-browser-install')?.addEventListener('click', () => browserSetup(true));
  card.querySelector('#btn-browser-remove')?.addEventListener('click', () => browserSetup(false));

  card.querySelectorAll('[data-forget]').forEach(btn =>
    btn.addEventListener('click', async () => {
      try {
        await vault.browserForget(btn.dataset.forget);
        await vault.commit();
        banner('Verknüpfung getrennt.', 'success');
        renderBrowserSection();
      } catch (err) {
        banner(`Trennen fehlgeschlagen: ${err.message}`, 'error');
      }
    }));
}

/** Trägt uns bei den Browsern ein — oder nimmt es zurück. */
async function browserSetup(install) {
  try {
    const results = install ? await vault.browserInstall() : await vault.browserUninstall();

    const ok = results.filter(r => r.ok).map(r => r.browser);
    const failed = results.filter(r => !r.ok);

    if (ok.length) {
      banner(`${install ? 'Eingerichtet' : 'Entfernt'}: ${ok.join(', ')}. Browser neu starten.`,
        'success', 8000);
    } else if (!failed.length) {
      banner('Kein eingerichteter Browser gefunden.', 'info');
    }

    for (const r of failed) {
      banner(`${r.browser}: ${r.note ?? 'fehlgeschlagen'}`, 'warning', 8000);
    }

    renderBrowserSection();
  } catch (err) {
    banner(`Fehlgeschlagen: ${err.message}`, 'error', 6000);
  }
}

/**
 * Einstellungen als volle Seite — auch vom Sperrbildschirm aus.
 *
 * Es gibt nur diesen einen Bauplan. Ohne offene Datenbank wird der
 * Abschnitt „Diese Datenbank" per CSS ausgeblendet (`[data-needs-db]`),
 * sonst ändert sich nichts.
 */
function openSettingsPage() {
  document.body.dataset.settingsOnly = 'true';
  $('#lockscreen').hidden = true;
  renderSettings();
  showView('settings');
}

function closeSettingsPage() {
  delete document.body.dataset.settingsOnly;
  resetToHomeView();
  $('#lockscreen').hidden = false;
  renderLockscreen();
}

/**
 * Verkabelt die Einstellungen.
 *
 * `immediate` unterscheidet die beiden Orte: Auf der Seite gibt es kein
 * „Fertig", dort wirkt jede Änderung sofort. Im Dialog wird nur die
 * Darstellung vorab gezeigt — geschrieben wird erst beim Abschicken, damit
 * „Abbrechen" wirklich nichts hinterlässt.
 */
function wireSettings(root = $('#settings-body')) {
  // Darstellung: sofort sichtbar und sofort gemerkt.
  root.querySelectorAll('[name="appearance.theme"]').forEach(el =>
    el.addEventListener('change', async () => {
      applyTheme(el.value);
      await settings.set('appearance.theme', el.value, { silent: true });
      updateSettingsPreview();
    }));

  root.querySelectorAll('[name="appearance.primary"]').forEach(el => {
    el.addEventListener('input', () => applyPrimary(el.value));
    el.addEventListener('change', async () => {
      await settings.set('appearance.primary', el.value, { silent: true });
      updateSettingsPreview();
    });
  });

  // Nur für die geöffnete Datenbank
  root.querySelectorAll('[data-set-db]').forEach(el => el.addEventListener('change', async () => {
    const value = el.type === 'checkbox' ? el.checked : el.type === 'number' ? Number(el.value) : el.value;
    await settings.setForDatabase(settings.get('database.current', null), el.dataset.setDb, value);
    banner('Einstellung gespeichert.', 'success', 1600);
  }));

  root.querySelectorAll('[data-set]').forEach(el => el.addEventListener('change', async () => {
    const value = el.type === 'checkbox' ? el.checked : el.type === 'number' ? Number(el.value) : el.value;
    await settings.set(el.dataset.set, value);

    // Die Ruhezeit hütet der Kern, nicht das Fenster — er muss sie erfahren.
    if (el.dataset.set === 'unlock.autoLockMinutes' && !state.locked) {
      await vault.setAutoLock(Number(value) || 0);
    }

    banner('Einstellung gespeichert.', 'success', 1600);
  }));

  root.querySelectorAll('[name="checks.automatic"]').forEach(el =>
    el.addEventListener('change', async () => {
      await settings.set('checks.automatic', el.value, { silent: true });
      updateSettingsPreview();
    }));

  root.querySelector('#btn-refresh-icons')?.addEventListener('click', () => {
    refreshEpoch();
    renderPasswords();
    renderHome();
    banner('Icons werden neu abgerufen.', 'success');
  });

  root.querySelector('#btn-adopt-titles')?.addEventListener('click', async () => {
    const withUrl = state.entries.filter(e => hostFromUrl(e.url));
    if (!withUrl.length) { banner('Kein Eintrag hat eine URL.', 'info'); return; }

    const res = await dialog({
      title: 'Namen übernehmen',
      content: `Bei <strong>${withUrl.length}</strong> Einträgen wird der Name durch den Titel der Website ersetzt.
                ${isTauri ? '' : '<br><br>Im Browser blockiert die Sicherheitsrichtlinie fremder Seiten den Abruf — dort wird ersatzweise der Hostname verwendet.'}`,
      confirmText: 'Übernehmen',
      cancelText: 'Abbrechen'
    });
    if (!(res?.submit ?? res)) return;
    await adoptTitles(withUrl);
  });

  root.querySelector('#btn-export')?.addEventListener('click', () => {
    settings.downloadSettings();
    banner('settings.json exportiert.', 'success');
  });

  root.querySelector('#btn-import')?.addEventListener('click', () => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = 'application/json,.json';
    input.addEventListener('change', async () => {
      const file = input.files?.[0];
      if (!file) return;
      try {
        await settings.importSettings(await file.text());
        applyAppearance(settings.get('appearance', {}));
        renderSettings();
        banner('Einstellungen importiert.', 'success');
      } catch (err) {
        banner(`Datei konnte nicht gelesen werden: ${err.message}`, 'error');
      }
    });
    input.click();
  });

  root.querySelector('#btn-pin-create')?.addEventListener('click', async () => {
    if (await createAppPin()) renderSettings();
  });
  root.querySelector('#btn-pin-change')?.addEventListener('click', changePin);
  root.querySelector('#btn-pin-clear')?.addEventListener('click', clearAppPin);
  root.querySelector('#btn-access')?.addEventListener('click', manageAccess);

  root.querySelector('#btn-empty-bin')?.addEventListener('click', async () => {
    const inBin = state.entries.filter(e => e.recycled).length;
    if (!inBin) { banner('Der Papierkorb ist leer.', 'info'); return; }

    let confirmed = false;
    try {
      const res = await dialog({
        title: 'Papierkorb leeren',
        content: `${inBin} ${inBin === 1 ? 'Eintrag wird' : 'Einträge werden'} endgültig
          entfernt. Das lässt sich nicht rückgängig machen.`,
        confirmText: 'Endgültig löschen',
        cancelText: 'Abbrechen'
      });
      confirmed = res?.submit ?? res === true;
    } catch { confirmed = false; }
    if (!confirmed) return;

    const removed = await vault.emptyRecycleBin();
    await vault.commit();
    await refreshFromVault();
    renderAll({ includeSettings: false });
    banner(`${removed} ${removed === 1 ? 'Eintrag' : 'Einträge'} endgültig gelöscht.`, 'success');
  });

  root.querySelector('#btn-reset')?.addEventListener('click', async () => {
    let confirmed = false;
    try {
      const res = await dialog({
        title: 'Einstellungen zurücksetzen',
        content: 'Alle Einstellungen werden auf die Standardwerte zurückgesetzt. Die Datenbank bleibt unverändert.',
        confirmText: 'Zurücksetzen',
        cancelText: 'Abbrechen'
      });
      confirmed = res?.submit ?? res === true;
    } catch {
      confirmed = false;
    }
    if (!confirmed) return;

    await settings.resetSettings();
    applyAppearance(settings.get('appearance', {}));
    state.expanded = new Set();
    renderSettings();
    banner('Auf Standard zurückgesetzt.', 'success');
  });
}

function updateSettingsPreview() {
  const pre = document.getElementById('settings-preview');
  if (pre) pre.textContent = settings.exportSettings();
}

/* =========================================================
   Ordner: anlegen, umbenennen, verschieben
   ========================================================= */

async function openFolderDialog({ parent = '', path = null } = {}) {
  const isEdit = Boolean(path);
  const currentName = isEdit ? path.split('/').pop() : '';
  const parentPath = isEdit ? path.split('/').slice(0, -1).join('/') : parent;

  const options = ['', ...vault.folders()].filter(f => !isEdit || (f !== path && !f.startsWith(`${path}/`)));

  const res = await dialog({
    title: isEdit ? `Ordner „${esc(currentName)}"` : 'Ordner anlegen',
    content: `
      <div class="dlg-field">
        <label for="fld-folder-name">Name</label>
        <div class="dlg-input-row"><input id="fld-folder-name" type="text" name="name" value="${esc(currentName)}" required></div>
      </div>
      <div class="dlg-field">
        <label for="fld-folder-parent">Übergeordneter Ordner</label>
        <div class="dlg-input-row">
          <select id="fld-folder-parent" name="parent">
            ${options.map(f => `<option value="${esc(f)}" ${f === parentPath ? 'selected' : ''}>${f ? esc(f) : '— oberste Ebene —'}</option>`).join('')}
          </select>
        </div>
      </div>`,
    confirmText: isEdit ? 'Speichern' : 'Anlegen',
    cancelText: 'Abbrechen'
  });

  if (!(res?.submit ?? res)) return;

  const name = String(res.data?.name ?? '').trim();
  const newParent = String(res.data?.parent ?? '');
  if (!name) { banner('Der Name darf nicht leer sein.', 'warning'); return; }
  if (name.includes('/')) { banner('Schrägstriche sind im Ordnernamen nicht erlaubt.', 'warning'); return; }

  if (isEdit) {
    if (name !== currentName) await vault.renameFolder(path, name);
    const renamedPath = [...path.split('/').slice(0, -1), name].join('/');
    if (newParent !== parentPath) await vault.moveFolder(renamedPath, newParent);
  } else {
    await vault.createFolder(newParent ? `${newParent}/${name}` : name);
  }

  await vault.commit();
  await refreshFromVault();
  renderAll({ includeSettings: false });
  banner(isEdit ? 'Ordner gespeichert.' : 'Ordner angelegt.', 'success');
}

/** Merkt sich gebündelt, welche Ordner offen sind. */
let expandedTimer = null;
function persistExpanded() {
  clearTimeout(expandedTimer);
  expandedTimer = setTimeout(() => {
    settings.set('ui.expandedFolders', [...state.expanded], { silent: true });
  }, 400);
}

/* =========================================================
   Verschieben und Einsortieren
   ---------------------------------------------------------
   Wird genau einmal eingerichtet. Vorher hing bei jedem Neuzeichnen
   ein weiterer Satz Zuhörer am selben Element — daher kamen Meldungen
   mehrfach. Die Zuordnung läuft über den Container, der bestehen
   bleibt, auch wenn sein Inhalt neu gebaut wird.
   ========================================================= */

let dragController = null;

function setupDragMove(host) {
  if (dragController) return;

  dragController = enableDragMove(host, {
    itemSelector: '[data-drag-id]',
    targetSelector: '[data-drop-path]',
    label: el => el.dataset.dragLabel || '',

    // Mitte eines Ordners: hineinlegen
    onDrop: (dragged, target) => moveInto(dragged.dataset.dragId, target.dataset.dropPath),

    // Rand eines Eintrags oder Ordners: davor oder dahinter einsortieren
    onReorder: (dragged, reference, position) =>
      placeNextTo(dragged.dataset.dragId, reference.dataset.dragId, position)
  });
}

async function moveInto(dragId, targetPath) {
  if (dragId.startsWith('entry:')) {
    const id = dragId.slice(6);

    // Zieht man einen aus einer Auswahl, kommen alle mit — sonst wäre
    // unklar, was die Kästchen überhaupt bewirken.
    const group = pick.isSelected(id) ? pick.selectedIds() : [id];
    const moving = group.filter(x => vault.getEntry(x)?.folder !== targetPath);
    if (!moving.length) return;

    for (const one of moving) await vault.moveEntry(one, targetPath);
    pick.clearSelection();

    return afterStructureChange(moving.length === 1
      ? `Nach „${targetPath}“ verschoben.`
      : `${moving.length} Einträge nach „${targetPath}“ verschoben.`);
  }

  const from = dragId.slice(7);
  if (from === targetPath) return;

  const ok = await vault.moveFolder(from, targetPath);
  if (!ok) return banner('Dieser Ordner lässt sich dorthin nicht verschieben.', 'warning');
  return afterStructureChange('Ordner verschoben.');
}

async function placeNextTo(dragId, refId, position) {
  if (!refId || dragId === refId) return;

  if (dragId.startsWith('entry:') && refId.startsWith('entry:')) {
    const ok = await vault.reorderEntry(dragId.slice(6), refId.slice(6), position);
    if (!ok) return;
    return afterStructureChange('Reihenfolge geändert.');
  }

  if (dragId.startsWith('folder:') && refId.startsWith('folder:')) {
    const ok = await vault.reorderFolder(dragId.slice(7), refId.slice(7), position);
    if (!ok) return banner('Dieser Ordner lässt sich dorthin nicht verschieben.', 'warning');
    return afterStructureChange('Reihenfolge geändert.');
  }

  // Eintrag neben einem Ordner: in dessen Elternordner einordnen
  if (dragId.startsWith('entry:') && refId.startsWith('folder:')) {
    const parent = refId.slice(7).split('/').slice(0, -1).join('');
    return moveInto(dragId, parent);
  }
}

async function afterStructureChange(message) {
  await vault.commit();
  await refreshFromVault();
  renderAll({ includeSettings: false });
  banner(message, 'success');
}

/* =========================================================
   Anlegen — Auswahl zwischen Formular und Kamera
   ========================================================= */

async function startCreation() {
  const scannable = qr.scannerAvailable();

  const res = await dialog({
    title: 'Neu anlegen',
    content: `
      <div class="choice-grid">
        <button type="button" class="choice" data-choice="manual">
          <span class="msr">edit_note</span>
          <strong>Eintrag anlegen</strong>
          <small>Name, Benutzername, Passwort selbst eingeben</small>
        </button>
        <button type="button" class="choice" data-choice="files">
          <span class="msr">folder_zip</span>
          <strong>Dateien ablegen</strong>
          <small>Dokumente verschlüsselt in der Datenbank aufbewahren</small>
        </button>
        <button type="button" class="choice" data-choice="folder">
          <span class="msr">create_new_folder</span>
          <strong>Ordner anlegen</strong>
          <small>Zum Sortieren der Einträge</small>
        </button>
        <button type="button" class="choice" data-choice="camera" ${scannable ? '' : 'disabled'}>
          <span class="msr">qr_code_scanner</span>
          <strong>QR-Code scannen</strong>
          <small>${scannable ? 'TOTP einrichten oder einen Sammelexport einlesen' : 'In diesem Browser nicht verfügbar'}</small>
        </button>
        <button type="button" class="choice" data-choice="file" ${scannable ? '' : 'disabled'}>
          <span class="msr">image_search</span>
          <strong>QR-Code aus Bild</strong>
          <small>${scannable ? 'Screenshot oder Foto auswählen' : 'In diesem Browser nicht verfügbar'}</small>
        </button>
      </div>`,
    confirmText: 'Abbrechen',
    onlyConfirm: true,
    onInsert: () => queueMicrotask(() => {
      document.querySelectorAll('.choice[data-choice]').forEach(btn =>
        btn.addEventListener('click', () => {
          window.__wkChoice = btn.dataset.choice;
          closeHostDialog(btn, true);
        }));
    })
  });

  const choice = window.__wkChoice;
  window.__wkChoice = null;
  if (!choice) return;

  if (choice === 'manual') { openEntryDialog(null); return; }
  if (choice === 'files') { openEntryDialog(null, {}, { mode: 'files' }); return; }
  if (choice === 'folder') { openFolderDialog(); return; }

  try {
    const value = choice === 'camera' ? await scanWithCamera() : await scanFromFile();
    if (value) await handleScan(value);
  } catch (err) {
    if (err.message !== 'abgebrochen') banner(`Scan fehlgeschlagen: ${err.message}`, 'error', 5000);
  }
}

async function scanFromFile() {
  return new Promise((resolve, reject) => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = 'image/*';
    input.addEventListener('change', async () => {
      const file = input.files?.[0];
      if (!file) return reject(new Error('abgebrochen'));
      try { resolve(await qr.scanFile(file)); } catch (err) { reject(err); }
    });
    input.click();
  });
}

/** Wertet einen gescannten Inhalt aus und legt daraus etwas Sinnvolles an. */
async function handleScan(value) {
  let parsed;
  try { parsed = qr.interpret(value); }
  catch (err) { banner(`Code nicht lesbar: ${err.message}`, 'error', 5000); return; }

  switch (parsed.kind) {
    case 'migration':
      return importMigration(parsed.accounts);

    case 'totp':
      return placeTotp(parseOtpauth(parsed.uri));

    case 'wifi':
      return openEntryDialog(null, {
        name: parsed.name, username: parsed.username,
        password: parsed.password, notes: parsed.notes
      });

    case 'url':
      return openEntryDialog(null, { name: parsed.name, url: parsed.url });

    case 'fido':
      banner('Das ist ein Anmelde-Code für Passkeys, keine übertragbaren Zugangsdaten. Passkeys legt der Systemdialog der Website an.', 'info', 8000);
      return;

    default:
      return openEntryDialog(null, { notes: parsed.text });
  }
}

/** Ein einzelnes TOTP: neuer Eintrag oder an einen bestehenden anhängen. */
async function placeTotp(parsed) {
  if (!parsed?.secret) { banner('Im Code steckt kein TOTP-Secret.', 'warning'); return; }

  const candidates = state.entries.filter(e => !e.hasTotp);
  const suggestion = state.entries.find(e =>
    (parsed.issuer && e.name.toLowerCase().includes(parsed.issuer.toLowerCase())) ||
    (parsed.issuer && e.url.toLowerCase().includes(parsed.issuer.toLowerCase())));

  const res = await dialog({
    title: 'TOTP hinzufügen',
    content: `
      <p class="dlg-note">Gefunden: <strong>${esc(parsed.issuer || parsed.name || 'Konto')}</strong></p>
      <div class="choice-grid">
        <button type="button" class="choice" data-target="new">
          <span class="msr">add_circle</span><strong>Neuer Eintrag</strong>
          <small>Legt einen eigenen Eintrag dafür an</small>
        </button>
        <button type="button" class="choice" data-target="existing" ${candidates.length ? '' : 'disabled'}>
          <span class="msr">link</span><strong>Zu bestehendem Eintrag</strong>
          <small>${candidates.length ? 'An einen vorhandenen Eintrag anhängen' : 'Alle Einträge haben schon ein TOTP'}</small>
        </button>
      </div>
      <div class="dlg-field" id="pick-existing" hidden>
        <label for="totp-target">Eintrag auswählen</label>
        <div class="dlg-input-row">
          <select id="totp-target">
            ${candidates.map(e => `<option value="${e.id}" ${suggestion?.id === e.id ? 'selected' : ''}>${esc(e.name)}${e.username ? ` — ${esc(e.username)}` : ''}</option>`).join('')}
          </select>
        </div>
      </div>`,
    confirmText: 'Übernehmen',
    cancelText: 'Abbrechen',
    onInsert: () => queueMicrotask(() => {
      document.querySelectorAll('.choice[data-target]').forEach(btn =>
        btn.addEventListener('click', () => {
          window.__wkTarget = btn.dataset.target;
          document.querySelectorAll('.choice[data-target]').forEach(b =>
            b.setAttribute('aria-pressed', String(b === btn)));
          const picker = document.getElementById('pick-existing');
          if (picker) picker.hidden = btn.dataset.target !== 'existing';
        }));
    })
  });

  if (!(res?.submit ?? res)) { window.__wkTarget = null; return; }

  const target = window.__wkTarget;
  window.__wkTarget = null;

  const config = { digits: parsed.digits, period: parsed.period, algorithm: parsed.algorithm };

  if (target === 'existing') {
    const id = res.data?.['totp-target'] ?? document.getElementById('totp-target')?.value;
    const entry = vault.getEntry(id);
    if (!entry) { banner('Eintrag nicht gefunden.', 'error'); return; }

    const token = await vault.setSecret(null, parsed.secret);
    await vault.saveEntry({ ...entry, hasTotp: true, totpToken: token, totpConfig: config });
    await vault.commit();
    await refreshFromVault();
    renderAll({ includeSettings: false });
    banner(`TOTP zu „${entry.name}“ hinzugefügt.`, 'success');
    return;
  }

  openEntryDialog(null, {
    name: parsed.issuer || parsed.name,
    username: parsed.name,
    totpSecret: parsed.secret,
    totpConfig: config
  });
}

/** Sammelexport: jedes Konto wird ein eigener Eintrag. */
async function importMigration(accounts) {
  const res = await dialog({
    title: 'Sammelexport gefunden',
    content: `
      <p class="dlg-note">Der Code enthält <strong>${accounts.length}</strong> Konten. Jedes wird als eigener Eintrag angelegt.</p>
      <ul class="import-list">
        ${accounts.map(a => `<li><strong>${esc(a.issuer || a.name)}</strong><span>${esc(a.name)}</span></li>`).join('')}
      </ul>`,
    confirmText: `${accounts.length} Einträge anlegen`,
    cancelText: 'Abbrechen'
  });

  if (!(res?.submit ?? res)) return;

  let created = 0;
  for (const account of accounts) {
    if (account.type !== 'totp') continue;   // HOTP zählt anders und wird ausgelassen

    const token = await vault.setSecret(null, account.secret);
    await vault.saveEntry({
      id: null,
      name: account.issuer || account.name,
      folder: 'Importiert',
      username: account.name,
      url: '', notes: '', tags: ['Importiert'],
      passkey: false, expires: null,
      hasPassword: false, passwordToken: null,
      hasTotp: true, totpToken: token,
      totpConfig: { digits: account.digits, period: account.period, algorithm: account.algorithm },
      attachments: []
    });
    created++;
  }

  await vault.commit();
  await refreshFromVault();
  renderAll({ includeSettings: false });

  const skipped = accounts.length - created;
  banner(`${created} Einträge angelegt${skipped ? `, ${skipped} übersprungen (kein TOTP)` : ''}.`, 'success', 5000);
}

/* =========================================================
   Eintrags-Dialog
   ========================================================= */
/**
 * Eintrag bearbeiten oder anlegen.
 *
 * Zwei Ansichten desselben Formulars: `full` mit allen Feldern und `files`
 * als reine Dateiablage — Name, Ordner, Dateien, Notizen. Reine
 * Dateiablagen (siehe `isFileEntry`) gehen von selbst als `files` auf; oben
 * im Dialog lässt sich jederzeit umschalten. Das Umschalten blendet nur
 * aus, es verwirft nichts: Gespeichert wird in beiden Fällen dasselbe.
 *
 * `files` sind bereits eingelesene Anhänge (`staged:`), etwa aus dem
 * Ablegen aufs Fenster.
 */
async function openEntryDialog(id, prefill = {}, { mode = null, files = [] } = {}) {
  const e = id != null ? vault.getEntry(id) : {
    id: null, folder: vault.folders()[0] ?? 'Allgemein', name: '', username: '', url: '',
    notes: '', tags: [], passkey: false, expires: null, attachments: [],
    hasPassword: false, passwordToken: null,
    hasTotp: false, totpToken: null,
    totpConfig: { digits: 6, period: 30, algorithm: 'SHA1' }
  };
  if (!e) return;

  // Werte aus einem Scan vorbelegen
  Object.assign(e, {
    name: prefill.name ?? e.name,
    username: prefill.username ?? e.username,
    url: prefill.url ?? e.url,
    notes: prefill.notes ?? e.notes,
    folder: prefill.folder ?? e.folder
  });
  if (prefill.totpConfig) e.totpConfig = prefill.totpConfig;

  const initialMode = mode ?? (e.id && isFileEntry(e) ? 'files' : 'full');
  state.dialogEntryId = e.id;
  if (e.id) markUsed(e.id);

  state.dialogAttachments = await loadAttachments(e);
  await addStagedAttachments(files);

  // Geheimnisse bleiben im Kern. Die Felder starten leer; erst „anzeigen"
  // holt den Wert, und nur ein tatsächlich geänderter Wert wird geschrieben.
  state.secretEdits = {
    password: prefill.password ?? null,
    totp: prefill.totpSecret ?? null
  };
  const prefilled = { password: Boolean(prefill.password), totp: Boolean(prefill.totpSecret) };

  const t = e.totpConfig ?? { digits: 6, period: 30, algorithm: 'SHA1' };
  const strength = e.id ? state.strength.get(e.id) : null;

  const content = `
    <div class="mode-switch" role="tablist" aria-label="Ansicht">
      <button type="button" role="tab" data-mode="files"><span class="msr">folder_zip</span>Dateien</button>
      <button type="button" role="tab" data-mode="full"><span class="msr">key</span>Alle Felder</button>
    </div>

    <div class="dlg-field">
      <label for="fld-name">Name</label>
      <div class="dlg-input-row"><input id="fld-name" type="text" name="name" value="${esc(e.name)}" required></div>
    </div>

    <div class="dlg-grid">
      <div class="dlg-field">
        <label for="fld-folder">Ordner</label>
        <div class="dlg-input-row"><input id="fld-folder" type="text" name="folder" list="folder-options" value="${esc(e.folder)}"></div>
      </div>
      <div class="dlg-field">
        <label for="fld-tags">Tags (Komma)</label>
        <div class="dlg-input-row"><input id="fld-tags" type="text" name="tags" value="${esc((e.tags ?? []).join(', '))}"></div>
      </div>
    </div>

    <div class="dlg-field" data-only="full">
      <label for="fld-url">URL</label>
      <div class="dlg-input-row"><input id="fld-url" type="text" name="url" value="${esc(e.url)}"></div>
    </div>

    <!-- ===== Passwort ===== -->
    <details class="dlg-section" data-only="full" ${e.hasPassword || prefilled.password ? 'open' : ''}>
      <summary><span class="msr">key</span>Passwort<span class="dlg-section-hint">${esc(e.username) || (e.hasPassword ? 'gesetzt' : 'leer')}</span></summary>
      <div class="dlg-section-body">
        <div class="dlg-field">
          <label for="fld-username">Benutzername</label>
          <div class="dlg-input-row">
            <input id="fld-username" type="text" name="username" value="${esc(e.username)}">
            <button type="button" class="button" data-shape="round" id="dlg-copy-user" title="Kopieren"><span class="msr">content_copy</span></button>
          </div>
        </div>
        <div class="dlg-field">
          <label for="fld-password">Passwort</label>
          <div class="dlg-input-row">
            <input id="fld-password" type="password" autocomplete="new-password"
                   value="${prefilled.password ? esc(prefill.password) : (e.hasPassword ? SECRET_MASK : '')}"
                   placeholder="${e.hasPassword || prefilled.password ? '' : 'noch keins gesetzt'}">
            <button type="button" class="button" data-shape="round" id="dlg-reveal-pw" title="Anzeigen" ${e.hasPassword ? '' : 'disabled'}><span class="msr">visibility</span></button>
            <button type="button" class="button" data-shape="round" id="dlg-gen-pw" title="Neu erzeugen"><span class="msr">autorenew</span></button>
            <button type="button" class="button" data-shape="round" id="dlg-copy-pw" title="Kopieren" ${e.hasPassword ? '' : 'disabled'}><span class="msr">content_copy</span></button>
          </div>
          <div class="strength-meter" id="dlg-strength" data-score="${strength?.score ?? 0}">
            <div class="strength-bars"><span></span><span></span><span></span><span></span></div>
            <div class="strength-text">
              <span id="dlg-strength-label">${strength ? `Stärke: ${esc(strength.label)}` : '—'}</span>
              <span id="dlg-strength-extra">${strength ? `${strength.entropy} Bit` : ''}</span>
            </div>
          </div>
          <p class="dlg-note">Das gespeicherte Passwort liegt im Kern. Es wird erst geholt, wenn du das Feld anklickst oder auf „Anzeigen“ gehst — und nur dann, wenn du es wirklich änderst, auch geschrieben.</p>
        </div>
        <div class="dlg-field">
          <label for="fld-expires">Ablaufdatum (optional)</label>
          <div class="dlg-input-row">
            <input id="fld-expires" type="date" name="expires" value="${esc(e.expires ?? '')}">
            <button type="button" class="button" data-shape="round" id="dlg-clear-expiry" title="Ablaufdatum entfernen"><span class="msr">event_busy</span></button>
          </div>
        </div>
      </div>
    </details>

    <!-- ===== TOTP ===== -->
    <details class="dlg-section" data-only="full" ${e.hasTotp || prefilled.totp ? 'open' : ''}>
      <summary><span class="msr">timer</span>TOTP<span class="dlg-section-hint">${e.hasTotp ? 'eingerichtet' : 'nicht eingerichtet'}</span></summary>
      <div class="dlg-section-body">
        <div class="dlg-field">
          <label for="fld-totp">Secret (Base32) oder otpauth://-URI</label>
          <div class="dlg-input-row">
            <input id="fld-totp" type="password" autocomplete="off"
                   value="${prefilled.totp ? esc(prefill.totpSecret) : (e.hasTotp ? SECRET_MASK : '')}"
                   placeholder="${e.hasTotp || prefilled.totp ? '' : 'JBSWY3DPEHPK3PXP'}">
            <button type="button" class="button" data-shape="round" id="dlg-reveal-totp" title="Anzeigen" ${e.hasTotp ? '' : 'disabled'}><span class="msr">visibility</span></button>
            <button type="button" class="button" data-shape="round" id="dlg-scan-cam" title="QR-Code scannen"><span class="msr">qr_code_scanner</span></button>
            <button type="button" class="button" data-shape="round" id="dlg-scan-file" title="QR-Code aus Bild"><span class="msr">image_search</span></button>
          </div>
        </div>
        <div class="dlg-grid">
          <div class="dlg-field">
            <label for="fld-digits">Stellen</label>
            <div class="dlg-input-row"><input id="fld-digits" type="number" name="digits" min="6" max="8" value="${t.digits}"></div>
          </div>
          <div class="dlg-field">
            <label for="fld-period">Intervall (Sek.)</label>
            <div class="dlg-input-row"><input id="fld-period" type="number" name="period" min="10" max="120" value="${t.period}"></div>
          </div>
        </div>
        <div class="dlg-field">
          <label for="fld-algorithm">Algorithmus</label>
          <div class="dlg-input-row">
            <select id="fld-algorithm" name="algorithm">
              ${['SHA1', 'SHA256', 'SHA512'].map(a => `<option value="${a}" ${t.algorithm === a ? 'selected' : ''}>${a}</option>`).join('')}
            </select>
          </div>
        </div>
        <button type="button" class="button" data-shape="full" id="dlg-show-qr" ${e.hasTotp || prefilled.totp ? '' : 'disabled'}><span class="msr">qr_code_2</span>&nbsp;QR-Code</button>
      </div>
    </details>

    <!-- ===== Passkey ===== -->
    <details class="dlg-section" data-only="full" ${e.passkey ? 'open' : ''}>
      <summary><span class="msr">passkey</span>Passkey<span class="dlg-section-hint">${e.passkey ? 'hinterlegt' : 'keiner'}</span></summary>
      <div class="dlg-section-body">
        <div class="setting" style="padding:0;border:none">
          <div class="setting-label"><strong>Passkey hinterlegt</strong><small>Wird später von der Rust-Anbindung gesetzt</small></div>
          <div class="setting-control"><input type="checkbox" data-shape="toggle" name="passkey" ${e.passkey ? 'checked' : ''}></div>
        </div>
      </div>
    </details>

    <!-- ===== Anhänge — immer sichtbar ===== -->
    <div class="dlg-plain">
      <div class="dlg-plain-head">
        <span class="msr">attach_file</span><span id="dlg-att-title">Anhänge</span>
        <span class="dlg-plain-hint" id="dlg-att-count">${(e.attachments ?? []).length}</span>
      </div>
      <div class="attachment-grid" id="dlg-attachments"></div>
      <div class="dlg-attach-actions">
        <button type="button" class="button" data-shape="full" id="btn-attach">
          <span class="msr">upload_file</span>&nbsp;<span id="btn-attach-text">Datei anhängen …</span>
        </button>
        <button type="button" class="button" data-shape="full" id="btn-new-file" data-only="files">
          <span class="msr">note_add</span>&nbsp;Neue Datei …
        </button>
      </div>
    </div>

    <div class="dlg-plain" id="dlg-notes-block">
      <div class="dlg-plain-head"><span class="msr">notes</span>Notizen</div>
      <textarea id="fld-notes" name="notes" rows="3">${esc(e.notes)}</textarea>
    </div>

    <datalist id="folder-options">${vault.folders().map(f => `<option value="${esc(f)}">`).join('')}</datalist>`;

  const result = await dialog({
    title: e.id ? esc(e.name) : (initialMode === 'files' ? 'Neue Dateiablage' : 'Neuer Eintrag'),
    content,
    confirmText: 'Speichern',
    cancelText: 'Abbrechen',
    onInsert: () => queueMicrotask(() => wireEntryDialog(e, prefilled, initialMode))
  });

  state.dialogEntryId = null;
  if (!(result?.submit ?? result)) { state.secretEdits = null; return; }

  const d = result.data ?? {};

  // --- Geheimnisse: nur bei echter Änderung anfassen ---
  let passwordToken = e.passwordToken;
  const newPassword = state.secretEdits?.password;
  if (newPassword !== null && newPassword !== undefined) {
    passwordToken = await vault.setSecret(passwordToken, newPassword);
  }

  let totpToken = e.totpToken;
  let totpConfig = { digits: Number(d.digits ?? 6), period: Number(d.period ?? 30), algorithm: String(d.algorithm ?? 'SHA1') };
  const newTotp = state.secretEdits?.totp;
  if (newTotp !== null && newTotp !== undefined) {
    const parsed = newTotp.startsWith('otpauth://') ? parseOtpauth(newTotp) : null;
    if (parsed) totpConfig = { digits: parsed.digits, period: parsed.period, algorithm: parsed.algorithm };
    totpToken = newTotp ? await vault.setSecret(totpToken, parsed?.secret ?? newTotp) : null;
  }

  // --- Der Eintrag bekommt nur die Verweise ---
  // Die Inhalte liegen längst im Kern: gespeicherte tragen ihre Nummer,
  // frisch ausgewählte ein `staged:`. `vault_save_entry` löst beides auf.
  const attachments = state.dialogAttachments.map(att => ({ name: att.name, ref: att.ref }));

  const saved = await vault.saveEntry({
    id: e.id,
    name: String(d.name ?? '').trim(),
    folder: String(d.folder ?? 'Allgemein').trim() || 'Allgemein',
    username: String(d.username ?? ''),
    url: String(d.url ?? ''),
    notes: String(d.notes ?? ''),
    tags: String(d.tags ?? '').split(',').map(x => x.trim()).filter(Boolean),
    passkey: d.passkey === true || d.passkey === 'true' || d.passkey === 'on',
    expires: String(d.expires ?? '') || null,
    hasPassword: Boolean(passwordToken),
    passwordToken,
    hasTotp: Boolean(totpToken),
    totpToken,
    totpConfig,
    attachments
  });

  // Erst jetzt schreibt der Kern die Datenbank verschlüsselt auf die Platte
  await vault.commit();

  const changedPassword = newPassword !== null && newPassword !== undefined;

  state.secretEdits = null;
  await refreshFromVault();
  renderAll({ includeSettings: false });
  banner('Eintrag gespeichert.', 'success');

  // Ein neu gesetztes Passwort wird sofort einzeln geprüft — nicht erst
  // beim nächsten Gesamtdurchlauf.
  if (changedPassword && settings.get('checks.passwordBreach', true)) {
    checkSingleEntry(saved?.id ?? e.id);
  }
}

/** Prüft ein einzelnes Passwort gegen die Leak-Datenbank. */
async function checkSingleEntry(id) {
  if (!id) return;
  const entry = vault.getEntry(id);
  if (!entry?.passwordToken) return;

  const hash = await vault.hashFor(entry);
  if (!hash) return;

  const result = await checkPwnedByHash(hash);
  if (result.error) return;

  state.pwned.set(id, result);
  renderPasswords();
  renderHome();

  if (result.found) {
    banner(`Achtung: Dieses Passwort taucht ${result.count.toLocaleString('de-DE')}× in bekannten Leaks auf.`, 'warning', 8000);
  }
}

function wireEntryDialog(entry, prefilled = {}, mode = 'full') {
  const pw = document.getElementById('fld-password');
  if (!pw) return;

  setEntryMode(mode);
  document.querySelectorAll('.mode-switch [data-mode]').forEach(btn =>
    btn.addEventListener('click', () => setEntryMode(btn.dataset.mode)));

  const meter = document.getElementById('dlg-strength');
  const label = document.getElementById('dlg-strength-label');
  const extra = document.getElementById('dlg-strength-extra');

  // Solange das Feld noch die Maske zeigt, steckt kein echter Wert darin.
  let loaded = !entry.passwordToken || Boolean(prefilled.password);

  /** Holt den echten Wert aus dem Kern — beim ersten Bearbeiten. */
  const ensureLoaded = async () => {
    if (loaded) return;
    loaded = true;
    pw.value = await vault.revealSecret(entry.passwordToken);
    // Nur Anzeigen zählt nicht als Änderung
    state.secretEdits.password = null;
  };

  const updateStrength = () => {
    const s = localStrength(pw.value);
    meter.dataset.score = s.score;
    label.textContent = `Stärke: ${s.label}`;
    extra.textContent = `${s.entropy} Bit`;
  };

  // Anklicken lädt den Wert, damit man direkt darin tippen kann
  pw.addEventListener('focus', ensureLoaded, { once: false });
  pw.addEventListener('pointerdown', ensureLoaded);

  pw.addEventListener('input', () => {
    if (!loaded) return;               // Tippen vor dem Laden ignorieren
    state.secretEdits.password = pw.value;
    updateStrength();
  });

  document.getElementById('dlg-reveal-pw')?.addEventListener('click', async () => {
    await ensureLoaded();
    pw.type = pw.type === 'password' ? 'text' : 'password';
  });

  document.getElementById('dlg-gen-pw')?.addEventListener('click', () => {
    loaded = true;
    pw.value = generatePassword(20);
    pw.type = 'text';
    state.secretEdits.password = pw.value;
    updateStrength();
  });

  document.getElementById('dlg-copy-pw')?.addEventListener('click', async () => {
    // Ungeladen: der Wert geht direkt aus dem Kern in die Zwischenablage
    if (!loaded) {
      const ok = await vault.copySecret(entry.passwordToken);
      if (ok) { banner('Passwort kopiert', 'success', 1800); scheduleClipboardClear(); }
      return;
    }
    copyPlain(pw.value, 'Passwort kopiert');
  });

  document.getElementById('dlg-copy-user')?.addEventListener('click', () =>
    copyPlain(document.getElementById('fld-username').value, 'Benutzername kopiert'));

  document.getElementById('dlg-clear-expiry')?.addEventListener('click', () => {
    document.getElementById('fld-expires').value = '';
  });

  wireTotpControls(entry, prefilled);
  wireAttachments();
}

/** Die Ansicht des Eintragsdialogs, oder `null`, wenn keiner offen ist. */
function entryMode() {
  return document.getElementById('dlg-attachments')?.closest('dialog')?.dataset.entryMode ?? null;
}

/** Schaltet den offenen Eintragsdialog zwischen Dateiablage und allen Feldern um. */
function setEntryMode(mode) {
  const host = document.getElementById('dlg-attachments')?.closest('dialog');
  if (!host) return;

  host.dataset.entryMode = mode;
  host.querySelectorAll('[data-only]').forEach(el => { el.hidden = el.dataset.only !== mode; });
  host.querySelectorAll('.mode-switch [data-mode]').forEach(btn =>
    btn.setAttribute('aria-selected', String(btn.dataset.mode === mode)));

  const files = mode === 'files';

  // Notizen gehören in der Dateiablage nicht zum Standard — sind aber welche
  // da, sollen sie nicht unsichtbar werden.
  const notes = document.getElementById('fld-notes');
  document.getElementById('dlg-notes-block').hidden = files && !notes?.value.trim();

  document.getElementById('dlg-att-title').textContent = files ? 'Dateien' : 'Anhänge';
  document.getElementById('btn-attach-text').textContent = files ? 'Dateien hinzufügen …' : 'Datei anhängen …';
  renderAttachments();
}

/* ---------- TOTP-Steuerung im Dialog ---------- */
function wireTotpControls(entry, prefilled = {}) {
  const field = document.getElementById('fld-totp');
  if (!field) return;

  let loaded = !entry.totpToken || Boolean(prefilled.totp);

  const ensureLoaded = async () => {
    if (loaded) return;
    loaded = true;
    field.value = await vault.revealSecret(entry.totpToken);
    state.secretEdits.totp = null;
  };

  field.addEventListener('focus', ensureLoaded);
  field.addEventListener('pointerdown', ensureLoaded);
  field.addEventListener('input', () => {
    if (loaded) state.secretEdits.totp = field.value;
  });

  document.getElementById('dlg-reveal-totp')?.addEventListener('click', async () => {
    await ensureLoaded();
    field.type = field.type === 'password' ? 'text' : 'password';
  });

  const applyUri = uri => {
    loaded = true;
    const p = parseOtpauth(uri);
    if (!p) { field.value = uri; state.secretEdits.totp = uri; return; }
    field.value = p.secret;
    state.secretEdits.totp = p.secret;
    const set = (id, v) => { const el = document.getElementById(id); if (el && v) el.value = v; };
    set('fld-digits', p.digits);
    set('fld-period', p.period);
    set('fld-algorithm', p.algorithm);
    const name = document.getElementById('fld-name');
    if (name && !name.value) name.value = p.issuer || p.name;
    document.getElementById('dlg-show-qr')?.removeAttribute('disabled');
  };

  document.getElementById('dlg-scan-cam')?.addEventListener('click', async () => {
    if (!qr.scannerAvailable()) { banner(scannerHint(), 'warning', 7000); return; }
    try {
      const uri = await scanWithCamera();
      if (uri) { applyUri(uri); banner('QR-Code übernommen.', 'success'); }
    } catch (err) {
      if (err.message !== 'abgebrochen') banner(`Scan fehlgeschlagen: ${err.message}`, 'error');
    }
  });

  document.getElementById('dlg-scan-file')?.addEventListener('click', () => {
    if (!qr.scannerAvailable()) { banner(scannerHint(), 'warning', 7000); return; }
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = 'image/*';
    input.addEventListener('change', async () => {
      const file = input.files?.[0];
      if (!file) return;
      try {
        applyUri(await qr.scanFile(file));
        banner('QR-Code übernommen.', 'success');
      } catch (err) { banner(err.message, 'error'); }
    });
    input.click();
  });

  document.getElementById('dlg-show-qr')?.addEventListener('click', async () => {
    const secret = loaded ? field.value.trim() : await vault.revealSecret(entry.totpToken);
    if (!secret) { banner('Kein TOTP-Secret hinterlegt.', 'warning'); return; }

    const uri = secret.startsWith('otpauth://') ? secret : buildOtpauth({
      name: document.getElementById('fld-name')?.value || 'Konto',
      issuer: document.getElementById('fld-url')?.value || '',
      secret,
      digits: Number(document.getElementById('fld-digits')?.value || 6),
      period: Number(document.getElementById('fld-period')?.value || 30),
      algorithm: document.getElementById('fld-algorithm')?.value || 'SHA1'
    });

    await showQrDialog(uri, document.getElementById('fld-name')?.value || 'TOTP');
  });
}

/** Zeigt einen QR-Code in einem eigenen Fenster — nur zum Ansehen. */
async function showQrDialog(uri, title) {
  await dialog({
    title: `QR-Code: ${esc(title)}`,
    content: `
      <div class="qr-output" id="qr-export"><p class="empty-state">Wird erzeugt …</p></div>
      <p class="dlg-note">Mit einer Authenticator-App abscannen. Der Code enthält das Secret im Klartext — nicht weitergeben und nicht abfotografieren lassen.</p>`,
    confirmText: 'Schließen',
    onlyConfirm: true,
    onInsert: () => queueMicrotask(async () => {
      const out = document.getElementById('qr-export');
      if (!out) return;
      out.innerHTML = '';
      await qr.renderQr(out, uri, {
        dots: resolvedColor('primary', 700),
        corners: resolvedColor('primary', 900),
        background: '#ffffff'
      });
    })
  });
}

function scannerHint() {
  return isTauri
    ? 'QR-Dekodierung nicht verfügbar. Füge die otpauth://-URI stattdessen als Text ein.'
    : 'Dieser Browser kann keine QR-Codes lesen — in der Desktop- und App-Version übernimmt das Rust. Füge die otpauth://-URI hier als Text ein.';
}

/** Kamera-Scan in einem eigenen Dialog. */
async function scanWithCamera() {
  let controller = null;
  let resolved = null;

  const res = await dialog({
    title: 'QR-Code scannen',
    content: `<div class="qr-scanner">
        <video id="qr-video" muted playsinline></video>
        <p class="empty-state" id="qr-hint" style="padding:0.5rem">Richte die Kamera auf den QR-Code.<br>
          <small>Auswertung: Rust (rqrr)</small></p>
      </div>`,
    confirmText: 'Fertig',
    cancelText: 'Abbrechen',
    onInsert: () => queueMicrotask(async () => {
      const video = document.getElementById('qr-video');
      const hint = document.getElementById('qr-hint');
      if (!video) return;
      try {
        controller = await qr.scanCamera(video);
        resolved = await controller.promise;
        if (hint) hint.textContent = 'Code erkannt.';
        document.querySelector('dialog[open] button[value="ok"], dialog[open] .dialog-submit')?.click();
      } catch (err) {
        if (hint && err.message !== 'abgebrochen') hint.textContent = `Kamera nicht verfügbar: ${err.message}`;
      }
    })
  });

  controller?.stop();
  if (!(res?.submit ?? res)) throw new Error('abgebrochen');
  return resolved;
}

/* ---------- Anhänge ----------
   Die Datei wird über den Dialog des Betriebssystems ausgewählt, nicht über
   ein `<input type="file">`. Der Kern liest sie ein und legt sie in seinen
   Zwischenspeicher; hierher kommen nur Name, Art, Größe und ein Verweis.

   Der Inhalt macht damit denselben Weg wie die Geheimnisse — er landet nie
   im Webview. Und es ist derselbe Dialog wie beim Öffnen einer Datenbank,
   also auch derselbe Zugriffsrahmen. Geschrieben wird beim Speichern des
   Eintrags: `vault_save_entry` löst die Verweise auf. */

function wireAttachments() {
  const button = document.getElementById('btn-attach');
  if (!button) return;

  renderAttachments();

  document.getElementById('btn-new-file')?.addEventListener('click', createEmptyFile);

  button.addEventListener('click', async () => {
    button.disabled = true;
    try {
      await addStagedAttachments(await vault.pickAttachments());
      renderAttachments();
    } catch (err) {
      banner(`Anhängen fehlgeschlagen: ${err.message}`, 'error', 6000);
    } finally {
      button.disabled = false;
    }
  });
}

/**
 * Nimmt eingelesene Anhänge in den offenen Dialog auf.
 *
 * Gemeinsamer Weg für den Auswahldialog und das Ablegen aufs Fenster.
 */
async function addStagedAttachments(picked = []) {
  for (const att of picked) {
    // Der Name ist in KDBX der Schlüssel des Anhangs — doppelte
    // ersetzen einander stillschweigend. Lieber vorher fragen.
    if (state.dialogAttachments.some(a => a.name === att.name)) {
      banner(`„${att.name}“ hängt bereits an diesem Eintrag.`, 'warning', 4000);
      continue;
    }
    // Für die Vorschau im Dialog wird der Inhalt geholt — derselbe Weg
    // wie bei den schon gespeicherten Anhängen in `loadAttachments`.
    const stored = await vault.attachmentData(att.ref);
    state.dialogAttachments.push({ ...att, data: stored?.data ?? '' });
  }
}

/**
 * Dateien, die aufs Fenster gezogen werden.
 *
 * Tauri fängt das Ablegen ab, bevor der Webview es sieht; der Kern liest
 * die Dateien ein und meldet nur die Verweise (siehe lib.rs). Ist ein
 * Eintrag offen, landen sie dort — sonst entsteht eine neue Dateiablage.
 */
async function bindFileDrops() {
  const dragging = on => {
    if (on) document.body.dataset.dragging = 'true';
    else delete document.body.dataset.dragging;
  };

  await listen('tauri://drag-enter', () => { if (!state.locked) dragging(true); });
  await listen('tauri://drag-leave', () => dragging(false));
  await listen('tauri://drag-drop', () => dragging(false));

  await listen('attachments-dropped', async ev => {
    dragging(false);
    const { staged = [], error = null } = ev?.payload ?? {};

    if (error) { banner(error, 'error', 6000); return; }
    if (!staged.length || state.locked) return;

    if (entryMode()) {
      await addStagedAttachments(staged);
      renderAttachments();
      return;
    }
    openEntryDialog(null, {}, { mode: 'files', files: staged });
  });
}

function renderAttachments() {
  const grid = document.getElementById('dlg-attachments');
  const count = document.getElementById('dlg-att-count');
  if (!grid) return;

  if (count) count.textContent = state.dialogAttachments.length;

  if (entryMode() === 'files') { renderFileList(grid); return; }
  grid.removeAttribute('data-layout');

  if (!state.dialogAttachments.length) {
    grid.innerHTML = `<p class="empty-state" style="grid-column:1/-1;padding:1rem">Noch keine Anhänge.</p>`;
    return;
  }

  grid.innerHTML = state.dialogAttachments.map((a, i) => {
    const kind = preview.kindOf(a);
    const thumb = kind === 'image'
      ? `<img src="${a.data}" alt="${esc(a.name)}">`
      : (kind === 'text' || kind === 'markdown')
        ? `<div class="attachment-text" data-snippet="${i}">…</div>`
        : `<span class="msr">${preview.iconFor(a)}</span>`;

    return `
      <div class="attachment" data-open-att="${i}" title="${esc(a.name)} — zum Anzeigen klicken">
        <div class="attachment-preview">${thumb}</div>
        <div class="attachment-meta">
          <span class="attachment-name">${esc(a.name)}</span>
          <span class="attachment-size">${formatBytes(a.size)}</span>
        </div>
        <button type="button" class="attachment-remove" data-remove="${i}" title="Entfernen"><span class="msr">close</span></button>
      </div>`;
  }).join('');

  grid.querySelectorAll('[data-remove]').forEach(btn => btn.addEventListener('click', ev => {
    ev.stopPropagation();
    state.dialogAttachments.splice(Number(btn.dataset.remove), 1);
    renderAttachments();
  }));

  grid.querySelectorAll('[data-open-att]').forEach(el => el.addEventListener('click', () =>
    openAttachmentViewer(state.dialogAttachments[Number(el.dataset.openAtt)])));

  // Textausschnitte nachladen, ohne das Rendern zu blockieren
  grid.querySelectorAll('[data-snippet]').forEach(async el => {
    const snippet = await preview.textSnippet(state.dialogAttachments[Number(el.dataset.snippet)], 120);
    el.textContent = snippet || '(leer)';
  });
}

/**
 * Dateiablage: eine Zeile je Datei statt Kacheln.
 *
 * Ein Klick zeigt die Datei, der Knopf rechts lädt sie herunter — mit
 * derselben Warnung wie in der Vorschau.
 */
function renderFileList(grid) {
  grid.dataset.layout = 'list';

  if (!state.dialogAttachments.length) {
    grid.innerHTML = `<div class="file-drop">
      <span class="msr">upload_file</span>
      <strong>Noch keine Dateien</strong>
      <small>Ziehe Dateien aufs Fenster, wähle sie unten aus oder lege eine neue an. Sie liegen danach verschlüsselt in der Datenbank.</small>
    </div>`;
    return;
  }

  grid.innerHTML = state.dialogAttachments.map((a, i) => `
    <div class="file-row" data-open-att="${i}" title="${esc(a.name)} — zum Anzeigen klicken">
      <span class="msr file-icon">${preview.iconFor(a)}</span>
      <span class="file-text">
        <strong>${esc(a.name)}</strong>
        <small>${formatBytes(a.size ?? 0)}${String(a.ref).startsWith('staged:') ? ' · noch nicht gespeichert' : ''}</small>
      </span>
      <button type="button" class="button" data-shape="round no-background" data-save-att="${i}" title="Herunterladen" aria-label="Herunterladen"><span class="msr">download</span></button>
      <button type="button" class="button" data-shape="round no-background" data-remove="${i}" title="Entfernen" aria-label="Entfernen"><span class="msr">delete</span></button>
    </div>`).join('');

  grid.querySelectorAll('[data-remove]').forEach(btn => btn.addEventListener('click', ev => {
    ev.stopPropagation();
    state.dialogAttachments.splice(Number(btn.dataset.remove), 1);
    renderAttachments();
  }));

  grid.querySelectorAll('[data-save-att]').forEach(btn => btn.addEventListener('click', ev => {
    ev.stopPropagation();
    downloadWithWarning(state.dialogAttachments[Number(btn.dataset.saveAtt)]);
  }));

  grid.querySelectorAll('[data-open-att]').forEach(el => el.addEventListener('click', () =>
    openAttachmentViewer(state.dialogAttachments[Number(el.dataset.openAtt)])));
}

/* ---------- Anhang-Vorschau ----------
   Eigenes Vollbild statt userDialog: oben Schließen, Dateiname und die
   Knöpfe, darunter die Datei auf der ganzen Fläche. userDialog bringt
   Titel, Fußzeile und eine Höchstbreite mit, die hier nur stören.
   Als natives <dialog> mit showModal liegt es auch über einem offenen
   Eintragsdialog, und Escape schließt nur die Vorschau.

   Textdateien lassen sich über den Knopf oben bearbeiten, jede Datei über
   ihren Namen umbenennen. Ist der Eintrag schon gespeichert, geht beides
   sofort in die Datenbank — ohne „Speichern" im Eintrag und ohne Meldung,
   außer es klappt nicht. Bei einem neuen Eintrag gibt es noch nichts, wohin
   geschrieben werden könnte; dann zählt erst sein „Speichern". */

/**
 * Schreibt einen Anhang des offenen Eintrags sofort in die Datenbank, falls
 * der Eintrag schon gespeichert ist. Sonst bleibt der Verweis, wie er ist,
 * und „Speichern" im Eintrag nimmt ihn mit. Liefert den gültigen Verweis.
 */
async function persistAttachment(name, ref, previous) {
  if (!state.dialogEntryId) return ref;
  return vault.writeAttachment({ entryId: state.dialogEntryId, name, ref, previous });
}

/** Dateiarten, die als Text bearbeitet werden können. */
const EDITABLE_KINDS = new Set(['text', 'markdown']);

async function openAttachmentViewer(att, { edit = false } = {}) {
  if (!att) return;
  if (state.dialogEntryId) markUsed(state.dialogEntryId);

  const viewer = document.createElement('dialog');
  viewer.className = 'file-viewer';
  viewer.innerHTML = `
    <header class="file-viewer-bar">
      <button type="button" class="button" data-shape="round no-background" data-viewer-close title="Schließen" aria-label="Schließen"><span class="msr">close</span></button>
      <div class="file-viewer-title">
        <button type="button" class="file-viewer-name" data-viewer-rename title="Umbenennen">
          <strong></strong><span class="msr">edit</span>
        </button>
        <input type="text" class="file-viewer-rename" hidden aria-label="Dateiname">
      </div>
      <button type="button" class="button" data-shape="round no-background" data-viewer-edit title="Bearbeiten" aria-label="Bearbeiten" hidden><span class="msr">edit_note</span></button>
      <button type="button" class="button" data-shape="round no-background" data-viewer-show title="Anzeigen" aria-label="Anzeigen" hidden><span class="msr">visibility</span></button>
      <button type="button" class="button" data-shape="round no-background" data-viewer-apply title="Speichern" aria-label="Speichern" hidden><span class="msr">check</span></button>
      <button type="button" class="button" data-shape="round no-background" data-viewer-save title="Herunterladen" aria-label="Herunterladen"><span class="msr">download</span></button>
    </header>
    <div class="file-viewer-body"></div>`;

  const $v = sel => viewer.querySelector(sel);
  const body = $v('.file-viewer-body');
  const nameInput = $v('.file-viewer-rename');

  let cleanup = () => {};
  let closed = false;
  let editor = null;          // Textfeld, solange bearbeitet wird
  let original = '';

  const editable = () => EDITABLE_KINDS.has(preview.kindOf(att));
  const dirty = () => Boolean(editor) && editor.value !== original;

  /** Knöpfe passend zur Ansicht: Bearbeiten — oder Anzeigen und Speichern. */
  const showButtons = () => {
    $v('[data-viewer-edit]').hidden = Boolean(editor) || !editable();
    $v('[data-viewer-show]').hidden = !editor;
    $v('[data-viewer-apply]').hidden = !editor;
  };

  const showName = () => {
    $v('.file-viewer-name strong').textContent = att.name;
    $v('.file-viewer-name').title = `${att.name} — umbenennen`;
  };

  const showPreview = async () => {
    cleanup();
    cleanup = () => {};
    editor = null;
    showButtons();
    body.innerHTML = '<p class="empty-state">Wird geladen …</p>';
    const release = await preview.renderPreview(body, att);
    if (closed) release(); else cleanup = release;
  };

  const showEditor = async () => {
    if (editor || !editable()) return;
    original = await preview.asText(att);
    cleanup();
    cleanup = () => {};
    body.innerHTML = '';
    editor = document.createElement('textarea');
    editor.className = 'file-editor';
    editor.spellcheck = false;
    editor.value = original;
    body.append(editor);
    showButtons();
    editor.focus();
  };

  /** Schreibt den bearbeiteten Text in den Eintrag. Bleibt im Bearbeiten. */
  const saveEdit = async () => {
    if (!dirty()) return true;
    const text = editor.value;

    try {
      const staged = await vault.stageContent(att.name, text);
      const stored = await vault.attachmentData(staged.ref);
      const ref = await persistAttachment(att.name, staged.ref, att.name);
      Object.assign(att, { ref, type: staged.type, size: staged.size, data: stored?.data ?? '' });
      original = text;
      renderAttachments();
      return true;
    } catch (err) {
      banner(`Speichern fehlgeschlagen: ${err.message}`, 'error', 6000);
      return false;
    }
  };

  /**
   * Vor jedem Verlassen des Bearbeitens: Gibt es ungespeicherte Änderungen,
   * wird gefragt. Ja speichert, Nein verwirft — danach geht es in beiden
   * Fällen weiter. Nur wenn das Speichern scheitert, bleibt alles, wie es ist.
   */
  const confirmLeave = async () => {
    if (!dirty()) return true;
    const res = await dialog({
      title: 'Änderungen speichern?',
      content: `„${esc(att.name)}“ wurde bearbeitet.`,
      confirmText: 'Ja',
      cancelText: 'Nein'
    });
    if (res?.submit) return saveEdit();
    original = editor.value;   // verworfen: nicht noch einmal fragen
    return true;
  };

  const requestClose = async () => {
    if (await confirmLeave()) viewer.close();
  };

  const startRename = () => {
    nameInput.value = att.name;
    $v('.file-viewer-name').hidden = true;
    nameInput.hidden = false;
    nameInput.focus();
    // Nur den Namen vor der Endung markieren, wie im Dateimanager.
    const dot = att.name.lastIndexOf('.');
    nameInput.setSelectionRange(0, dot > 0 ? dot : att.name.length);
  };

  const finishRename = async (apply) => {
    if (nameInput.hidden) return;
    const next = nameInput.value.trim();
    nameInput.hidden = true;
    $v('.file-viewer-name').hidden = false;
    if (!apply || next === att.name) return;

    if (!next || /[\\/]/.test(next)) {
      banner('Der Name darf nicht leer sein und keinen Schrägstrich enthalten.', 'warning');
      return;
    }
    if (state.dialogAttachments.some(a => a !== att && a.name === next)) {
      banner(`„${next}“ gibt es in diesem Eintrag schon.`, 'warning');
      return;
    }

    // Mit der Endung wechselt die Art — aus .md wird beim Umbenennen in
    // .txt reiner Text, und die Vorschau soll das auch so zeigen.
    try {
      att.ref = await persistAttachment(next, att.ref, att.name);
    } catch (err) {
      banner(`Umbenennen fehlgeschlagen: ${err.message}`, 'error', 6000);
      return;
    }
    att.name = next;
    att.type = preview.typeFromName(next);
    showName();
    renderAttachments();
    if (editor) showButtons(); else showPreview();
  };

  viewer.addEventListener('close', () => {
    closed = true;
    cleanup();
    viewer.remove();
  });
  // Escape: erst das Umbenennen abbrechen, sonst wie der Schließen-Knopf.
  viewer.addEventListener('cancel', ev => {
    ev.preventDefault();
    if (!nameInput.hidden) finishRename(false);
    else requestClose();
  });

  $v('[data-viewer-close]').addEventListener('click', requestClose);
  $v('[data-viewer-edit]').addEventListener('click', showEditor);
  $v('[data-viewer-show]').addEventListener('click', async () => {
    if (await confirmLeave()) showPreview();
  });
  $v('[data-viewer-apply]').addEventListener('click', saveEdit);
  $v('[data-viewer-save]').addEventListener('click', async () => {
    if (await confirmLeave()) downloadWithWarning(att);
  });
  $v('[data-viewer-rename]').addEventListener('click', startRename);
  nameInput.addEventListener('keydown', ev => {
    if (ev.key === 'Enter') { ev.preventDefault(); finishRename(true); }
  });
  nameInput.addEventListener('blur', () => finishRename(true));

  document.body.append(viewer);
  viewer.showModal();
  showName();

  if (edit && editable()) await showEditor();
  else await showPreview();
}

/** Dateiarten für „Neue Datei" — Endung, Anzeige und was anfangs drinsteht. */
const NEW_FILE_TYPES = [
  { ext: 'md', label: 'Markdown (.md)', content: name => `# ${name}\n\n` },
  { ext: 'txt', label: 'Text (.txt)', content: () => '' },
  { ext: 'html', label: 'HTML (.html)', content: name => `<!DOCTYPE html>\n<html lang="de">\n<head>\n  <meta charset="utf-8">\n  <title>${name}</title>\n</head>\n<body>\n\n</body>\n</html>\n` },
  { ext: 'json', label: 'JSON (.json)', content: () => '{\n  \n}\n' },
  { ext: 'csv', label: 'Tabelle (.csv)', content: () => '' },
  { ext: 'yml', label: 'YAML (.yml)', content: () => '' }
];

/**
 * Legt eine leere Textdatei im offenen Eintrag an und öffnet sie gleich
 * zum Bearbeiten.
 *
 * Schreibt der Nutzer selbst eine Endung in den Namen, gilt die — die
 * Auswahl ist nur die Vorgabe.
 */
async function createEmptyFile() {
  const res = await dialog({
    title: 'Neue Datei',
    content: `
      <div class="dlg-field">
        <label for="fld-new-file-name">Name</label>
        <div class="dlg-input-row"><input id="fld-new-file-name" type="text" name="newFileName" placeholder="Notiz" required></div>
      </div>
      <div class="dlg-field">
        <label for="fld-new-file-type">Art</label>
        <div class="dlg-input-row">
          <select id="fld-new-file-type" name="newFileType">
            ${NEW_FILE_TYPES.map(t => `<option value="${t.ext}">${t.label}</option>`).join('')}
          </select>
        </div>
      </div>`,
    confirmText: 'Anlegen',
    cancelText: 'Abbrechen',
    onInsert: () => queueMicrotask(() => document.getElementById('fld-new-file-name')?.focus())
  });
  if (!res?.submit) return;

  const base = String(res.data?.newFileName ?? '').trim();
  const type = NEW_FILE_TYPES.find(t => t.ext === res.data?.newFileType) ?? NEW_FILE_TYPES[0];
  if (!base) return;

  const hasExtension = /\.[a-z0-9]{1,8}$/i.test(base);
  const name = hasExtension ? base : `${base}.${type.ext}`;
  const title = name.replace(/\.[^.]+$/, '');

  if (state.dialogAttachments.some(a => a.name === name)) {
    banner(`„${name}“ gibt es in diesem Eintrag schon.`, 'warning');
    return;
  }

  try {
    const staged = await vault.stageContent(name, hasExtension ? '' : type.content(title));
    await addStagedAttachments([staged]);
    renderAttachments();
    openAttachmentViewer(state.dialogAttachments.find(a => a.ref === staged.ref), { edit: true });
  } catch (err) {
    banner(`Anlegen fehlgeschlagen: ${err.message}`, 'error', 6000);
  }
}

/**
 * Herunterladen — erst nach ausdrücklicher Warnung.
 *
 * In der Datenbank ist die Datei verschlüsselt. Auf der Platte ist sie das
 * nicht mehr, und das soll niemand nebenbei übersehen.
 */
async function downloadWithWarning(att) {
  if (!att) return;

  const res = await dialog({
    title: 'Unverschlüsselt speichern?',
    type: 'warning',
    content: `<p>„${esc(att.name)}“ liegt in der Datenbank verschlüsselt. Beim Herunterladen
      wird die Datei <strong>unverschlüsselt</strong> auf die Festplatte geschrieben.</p>
      <p>Danach kann sie jedes Programm und jeder mit Zugriff auf diesen Ordner lesen, und eine
      Synchronisierung nimmt sie womöglich mit. Lösche die Kopie, wenn du sie nicht mehr brauchst.</p>`,
    confirmText: 'Unverschlüsselt speichern',
    cancelText: 'Abbrechen'
  });

  if (!(res?.submit ?? res)) return;
  await saveAttachment(att);
}

/**
 * Schreibt einen Anhang als Datei — über den Kern, nicht über den Webview.
 *
 * Ein `<a download>` bewirkt hier nichts: WebKitGTK bringt in einem
 * eingebetteten View keine Download-Behandlung mit, der Klick verpufft
 * folgenlos. Deshalb fragt der Kern nach dem Ort und schreibt selbst.
 */
async function saveAttachment(att) {
  try {
    const path = await vault.saveAttachment(att.ref);
    if (path) banner(`Gespeichert unter ${path}`, 'success', 5000);
  } catch (err) {
    banner(`Speichern fehlgeschlagen: ${err.message}`, 'error', 6000);
  }
}

function fileIcon(type, name = '') {
  if (type.startsWith('video/')) return 'movie';
  if (type.startsWith('audio/')) return 'audio_file';
  if (type === 'application/pdf') return 'picture_as_pdf';
  if (/\.(zip|tar|gz|7z|rar)$/i.test(name)) return 'folder_zip';
  if (/\.(txt|md|json|xml|csv)$/i.test(name) || type.startsWith('text/')) return 'description';
  return 'draft';
}

function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 ** 2).toFixed(1)} MB`;
}

function generatePassword(length = 20) {
  const pool = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*+-=?';
  const bytes = crypto.getRandomValues(new Uint32Array(length));
  return [...bytes].map(b => pool[b % pool.length]).join('');
}

/* =========================================================
   Anhänge laden
   ========================================================= */
async function loadAttachments(entry) {
  const out = [];
  for (const att of entry.attachments ?? []) {
    if (att.ref === null || att.ref === undefined) continue;
    const stored = await vault.attachmentData(att.ref);
    if (stored) out.push({ name: att.name, type: stored.type, size: sizeOfDataUrl(stored.data), data: stored.data, ref: att.ref });
  }
  return out;
}

function sizeOfDataUrl(dataUrl) {
  const b64 = String(dataUrl).split(',')[1] ?? '';
  return Math.floor(b64.length * 3 / 4);
}

/* =========================================================
   Zwischenablage
   ---------------------------------------------------------
   Für Geheimnisse gibt es `vault.copySecret` — der Wert wandert dort
   direkt aus dem Kern in die Zwischenablage. `copyPlain` ist nur für
   unkritische Felder wie Benutzernamen.
   ========================================================= */
async function copyPlain(value, message) {
  try {
    await navigator.clipboard.writeText(value ?? '');
    banner(message, 'success', 1800);
    scheduleClipboardClear();
    return true;
  } catch {
    banner('Kopieren nicht möglich.', 'error');
    return false;
  }
}

let clipboardTimer = null;
function scheduleClipboardClear() {
  const secs = settings.get('unlock.clipboardClearSeconds', 30);
  if (!secs) return;
  clearTimeout(clipboardTimer);
  clipboardTimer = setTimeout(() => navigator.clipboard.writeText('').catch(() => {}), secs * 1000);
}

boot();
