/**
 * lock.js — Sperren und Entsperren.
 *
 * Alles vor und um die offene Datenbank: die Liste der zuletzt geöffneten
 * Dateien, der Sperrbildschirm, der Entsperr-Dialog, die PIN des Programms,
 * der Willkommensbildschirm, das Anlegen einer neuen Datenbank — und was
 * beim Entsperren und Sperren anläuft und endet (Takt, automatische
 * Prüfung).
 */

import * as vault from '../data/vault.js';
import * as settings from '../data/settings.js';
import * as pick from '../ui/multiselect.js';
import { isTauri, isMobile, invoke, unlockMethods, pickDatabaseFile, pickSavePath } from '../core/platform.js';
import { dialog, banner, closeHostDialog } from '../ui/libs.js';
import { state, $, $$, esc } from '../core/state.js';
import { renderAll, refreshFromVault } from '../core/render.js';
import { captureFields, fieldChecked, pinStrengthNote, passwordField, wirePasswordFields } from '../ui/formular.js';
import { tickTotp } from './totp.js';
import { restoreCheck, runSecurityCheck } from './checkup.js';
import { showView } from '../core/navigation.js';
import { handleScan } from '../dialogs/create.js';
import { STUFEN, openSettingsPage, renderSettings } from './settings.js';

/** Wie der gerätegebundene Weg heißt, etwa „Windows Hello". */
export function deviceName() {
  return state.unlock.deviceLabel ?? 'Biometrie';
}

/**
 * Entsperren anstoßen: mit Geräteschlüssel direkt, sonst über den Dialog.
 */
export function startUnlock() {
  if (state.unlock.device) unlock({ method: 'device' });
  else openUnlockDialog();
}


export function recentDatabases() {
  const list = settings.get('database.recent', []);
  return Array.isArray(list) ? list : [];
}

export async function rememberDatabase(entry) {
  const list = recentDatabases().filter(d => d.path !== entry.path);

  // Wo die Datei liegt, weiß unter Android nur der Kern: Er fragt den
  // Anbieter nach dem Dateinamen. Einmal merken reicht — die Auskunft kostet
  // jedes Mal einen Weg über die Java-Seite.
  const label = entry.label ?? await pfadAuskunft(entry.path);

  // Kam beim Auswählen kein Name heraus, nimm den Dateinamen aus der
  // Auskunft („Downloads — passwoerter.kdbx").
  const name = entry.name && entry.name !== 'Noch nicht geöffnet'
    ? entry.name
    : (label?.split('/').pop() ?? entry.name);

  list.unshift({ ...entry, name, label });
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
export function resetToHomeView() {
  state.view = 'home';
  $$('.view').forEach(v => v.toggleAttribute('data-active', v.id === 'view-home'));
  const body = $('#settings-body');
  if (body) body.innerHTML = '';
}

export async function showLockscreen(message = null) {
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
export const BRAND_MARK = `<img class="lock-mark" src="./logo.svg" alt="" width="128" height="128">`;

/**
 * Sperrbildschirm.
 *
 * Aufbau von oben nach unten: aktuelle Datenbank, Entsperren, neue Datenbank
 * anlegen, und ganz unten zugeklappt die zuletzt genutzten. Welcher Weg zum
 * Entsperren erscheint, entscheidet der Kern über `unlock_methods` — hier
 * wird nur angezeigt, was er anbietet.
 */
export function renderLockscreen(message) {
  // Nach einem erfolgreichen Entsperren bleibt die Beschäftigt-Markierung
  // sonst am Element hängen und die Karte wirkt beim nächsten Mal blockiert.
  $('#lock-card')?.removeAttribute('data-busy');

  const list = recentDatabases();
  const current = settings.get('database.current', null);
  const active = list.find(d => d.path === current);

  $('#lock-card').innerHTML = `
    ${BRAND_MARK}
    <h2>WKeePass</h2>
    ${message ? `<p class="lock-sub">${esc(message)}</p>` : ''}

    ${active
      ? `<div class="lock-current">
           <span class="msr">database</span>
           <span class="lock-current-text">
             <strong>${esc(active.name)}</strong>
             <small>${esc(pfadLabel(active.path, active.label))}</small>
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
            <span class="lock-db-text"><strong>${esc(d.name)}</strong><small>${esc(pfadLabel(d.path, d.label))}</small></span>
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
export async function openUnlockDialog() {
  const u = state.unlock;
  const fields = captureFields('pin', 'pw');
  const bioWeg = biometrieWeg(u);

  const res = await dialog({
    title: 'Entsperren',
    content: `
      ${u.biometric ? `<button type="button" class="button hightlight" data-shape="full" id="dlg-bio">
        <span class="msr">fingerprint</span>&nbsp;Mit Biometrie entsperren</button>` : ''}

      ${u.pin ? `<label class="field-label">App-PIN</label>
        ${passwordField('pin', 'PIN', { required: false })}` : ''}

      <label class="field-label">Master-Passwort${u.pin ? ' (falls die PIN nicht passt)' : ''}</label>
      ${passwordField('pw', 'Master-Passwort', { required: !u.pin })}

      ${bioWeg ? `<div class="setting">
        <div class="setting-label"><strong>Künftig mit Biometrie öffnen</strong>
          <small>${bioWeg === 'device'
            ? 'Ersetzt das Master-Passwort — der Schlüssel liegt im Sicherheitschip'
            : `Der Finger weist dich aus, der Schlüssel liegt im Schlüsselbund${u.pinSet ? '' : ' — dafür wird eine App-PIN festgelegt'}`}</small></div>
        <div class="setting-control"><input type="checkbox" data-shape="toggle" name="rememberBio"
          ${settings.get('unlock.biometrics', true) ? 'checked' : ''}></div>
      </div>` : ''}

      ${u.pin ? '' : `<div class="setting">
        <div class="setting-label"><strong>Künftig auch mit PIN öffnen</strong>
          ${u.pinSet ? '' : '<small>Dafür wird gleich eine App-PIN festgelegt</small>'}</div>
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
  const wantsBioSwitch = fieldChecked(res.data, 'rememberBio');
  // Ein Schalter, der beste Weg: der Chip, wo es ihn gibt, sonst der
  // Schlüsselbund mit dem Finger als Ausweis.
  const wantsDevice = wantsBioSwitch && bioWeg === 'device';
  const wantsBio = wantsBioSwitch && bioWeg === 'keyring';

  // PIN und Fingerabdruck hängen beide am App-Schlüssel, und der entsteht
  // erst mit der PIN des Programms. Ohne sie geht keins von beidem.
  let pin = '';
  if (wantsPin || wantsBio) {
    if (!state.unlock.pinSet && !(await createAppPin())) return;
    pin = await askAppPin();
  }

  unlock({
    method: 'password',
    secret: d.pw,
    remember: ((wantsPin || wantsBio) && pin) || wantsDevice
      ? {
          pin,
          allowPin: wantsPin && Boolean(pin),
          allowBiometric: wantsBio && Boolean(pin),
          allowDevice: wantsDevice
        }
      : null
  });
}

/**
 * Welcher Biometrie-Weg für diese Datenbank noch einzurichten ist.
 *
 * `device`   Der Chip gibt den Schlüssel nur nach der Prüfung heraus
 *            (Android-Keystore, Windows Hello). Ersetzt das Master-Passwort.
 * `keyring`  Der Finger ist nur Ausweis, der Schlüssel liegt im
 *            Schlüsselbund, und es braucht die App-PIN (Linux, macOS).
 * `null`     Nichts möglich — oder schon eingerichtet.
 */
function biometrieWeg(u) {
  if (u.device || u.biometric) return null;
  if (u.deviceAvailable) return 'device';
  if (u.biometricAvailable && u.keyring) return 'keyring';
  return null;
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
/**
 * Wo eine Datenbank liegt — in lesbar.
 *
 * Auf Android ist der „Pfad" eine Adresse wie
 * `content://org.nextcloud.documents/document/5092c86d…`. Die sagt niemandem
 * etwas; die Anwendung dahinter schon.
 */
const HERKUNFT = {
  'com.android.providers.downloads.documents': 'Downloads',
  'com.android.externalstorage.documents': 'Gerätespeicher',
  'com.android.providers.media.documents': 'Medien',
  'org.nextcloud.documents': 'Nextcloud',
  'com.google.android.apps.docs.storage': 'Google Drive'
};

/**
 * Der Name, unter dem eine Datenbank in der Liste steht — bevor sie einmal
 * offen war. Danach nimmt `rememberDatabase` den Namen aus der Datei selbst.
 */
export function dbName(path) {
  const text = String(path ?? '');
  if (!text.startsWith('content://')) return text.split(/[\\/]/).pop();

  const name = decodeURIComponent(text.split(/[/:]/).pop() ?? '');
  // Steckt kein Name in der Adresse, kennt ihn niemand: Android gibt beim
  // Auswählen und beim Anlegen nur eine Kennung zurück. Der richtige Name
  // steht in der Datenbank selbst und kommt beim ersten Öffnen.
  return name.includes('.') && !/^[0-9a-f]+$/i.test(name) ? name : 'Noch nicht geöffnet';
}

/** Fragt den Kern, wie die Datei heißt und wo sie liegt. */
async function pfadAuskunft(path) {
  if (!isTauri || !path) return null;
  try {
    return await invoke('path_label', { path });
  } catch {
    return null;
  }
}

export function pfadLabel(path, gemerkt = null) {
  if (gemerkt) return gemerkt;

  const text = String(path ?? '');
  if (!text.startsWith('content://')) return text;

  const authority = text.slice('content://'.length).split('/')[0];
  const name = decodeURIComponent(text.split(/[/:]/).pop() ?? '');
  const ort = HERKUNFT[authority] ?? authority.replace(/\.documents$/, '').split('.').pop();

  return name.includes('.') && !/^[0-9a-f]+$/i.test(name) ? `${ort} — ${name}` : ort;
}

/** Warum die Biometrie hier nicht angeboten wird. */
function biometrieFehlt() {
  if (!state.unlock.biometricAvailable) {
    return isMobile
      ? 'Kein Finger oder Gesicht hinterlegt — in den Android-Einstellungen einrichten.'
      : 'Auf dem Gerät nicht verfügbar';
  }
  return 'Ohne Schlüsselbund nicht möglich';
}

export async function showWelcome() {
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
              <small>${state.unlock.keyring && state.unlock.biometricAvailable ? '' : biometrieFehlt()}</small>
            </div>
            <div class="setting-control">
              <input type="checkbox" data-shape="toggle" id="wc-bio"
                ${state.unlock.keyring && state.unlock.biometricAvailable ? '' : 'disabled'}>
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

  const name = dbName(picked);
  await rememberDatabase({ name, path: picked });
  // Die Entsperrwege gehören zur Datei. Ohne das bot der Dialog noch PIN
  // und Fingerabdruck der vorher gewählten Datenbank an.
  state.unlock = await unlockMethods(picked);
  renderLockscreen();
}

/* =========================================================
   Die PIN des Programms
   ---------------------------------------------------------
   Eine PIN für alles, einmal festgelegt. Pro Datenbank wird dann nur noch
   entschieden, ob sie damit — oder per Fingerabdruck — aufgehen darf.
   ========================================================= */


/** Legt die PIN des Programms fest. Muss vor jeder Freigabe geschehen. */
export async function createAppPin() {
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
export async function manageAccess() {
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
          ${state.unlock.keyring && state.unlock.biometricAvailable ? '' : 'disabled'}>
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
export async function clearAppPin() {
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
export async function changePin() {
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
 * Legt eine neue, leere Datenbank an und öffnet sie gleich.
 *
 * Erst Name und Master-Passwort, dann der Speicherort. Die Reihenfolge ist
 * Absicht: Der Name gehört in die Datei selbst, und unter Android ist er die
 * einzige Bezeichnung, die später noch da ist — aus einer
 * `content://`-Adresse lässt sich kein Dateiname herausholen.
 */
async function createDatabase() {
  const fields = captureFields('pw', 'pw2');

  const res = await dialog({
    title: 'Neue Datenbank anlegen',
    content: `<div class="dlg-field">
        <label for="fld-db-name">Name der Datenbank</label>
        <div class="dlg-input-row">
          <input id="fld-db-name" type="text" name="dbName" placeholder="Passwörter" autocomplete="off">
        </div>
      </div>
      <div class="dlg-field">
        <label for="fld-db-level">Verschlüsselungsstärke</label>
        <div class="dlg-input-row">
          <select id="fld-db-level" name="dbLevel" data-sp-picker data-sp-search="false">
            ${STUFEN.map(([wert, label, hinweis]) =>
              `<option value="${wert}" ${wert === 'standard' ? 'selected' : ''}>${label} — ${hinweis}</option>`).join('')}
          </select>
        </div>
      </div>
      <p>Das Master-Passwort ist der Hauptschlüssel. Es gibt keine
      Wiederherstellung — ist es weg, sind die Einträge weg.</p>
      ${passwordField('pw', 'Master-Passwort', { minlength: 1 })}
      ${passwordField('pw2', 'Master-Passwort wiederholen', { minlength: 1 })}`,
    confirmText: 'Weiter zum Speicherort',
    cancelText: 'Abbrechen',
    onInsert: fields.onInsert
  });

  if (!res?.submit) return;

  const name = String(res.data?.dbName ?? '').trim() || 'Passwörter';
  const level = String(res.data?.dbLevel ?? 'standard');
  const pw = fields.value('pw', res.data);

  if (!pw) { banner('Ohne Master-Passwort geht es nicht.', 'warning'); return; }
  if (pw !== fields.value('pw2', res.data)) { banner('Die beiden Passwörter stimmen nicht überein.', 'warning'); return; }

  // Aus „Passwörter privat" wird „passwoerter-privat.kdbx" als Vorschlag.
  const datei = `${name.toLowerCase()
    .replace(/ä/g, 'ae').replace(/ö/g, 'oe').replace(/ü/g, 'ue').replace(/ß/g, 'ss')
    .replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'passwoerter'}.kdbx`;

  const path = await pickSavePath(datei);
  if (!path) { banner('Es wurde kein Speicherort ausgewählt.', 'info'); return; }

  try {
    const info = await vault.create({
      path, password: pw, name,
      autoLockMinutes: Number(settings.get('unlock.autoLockMinutes', 5)) || 0
    });

    // Die Stufe steht erst in der offenen Datenbank; sie zu setzen schreibt
    // die Datei gleich noch einmal — beim Anlegen fällt das nicht auf.
    if (level !== 'standard') await vault.setSecurity({ level });
    await rememberDatabase({ name: info.name, path: info.path });
    await settings.set('database.current', info.path, { silent: true });

    banner('Datenbank angelegt.', 'success');
    await enterUnlocked();
  } catch (err) {
    banner(`Anlegen fehlgeschlagen: ${err.message}`, 'error', 7000);
  }
}

/** Alles, was nach dem Öffnen zu tun ist. */
export async function enterUnlocked() {
  state.locked = false;
  delete document.body.dataset.locked;
  $('#lockscreen').hidden = true;
  $('#btn-add').hidden = false;

  await refreshFromVault();
  await vault.ensurePasskeyFolder();
  restoreCheck();

  renderAll();
  showView(settings.get('ui.startView', 'home'));

  startTicker();
  maybeAutoCheck();

  // Fehlende Website-Icons nachholen — im Hintergrund, der Kern speichert sie
  // in der Datenbank und meldet sich mit `vault-changed`.
  vault.fetchIcons().catch(() => {});

  // Kam ein otpauth://-Code aus der Kamera-App, während gesperrt war?
  if (state.pendingOtp) {
    const uri = state.pendingOtp;
    state.pendingOtp = null;
    handleScan(uri);
  }
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
export function unlockBusy() {
  return unlocking;
}

export async function unlock({ method = 'password', secret = null, remember = null } = {}) {
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
      if (path) await rememberDatabase({ name: dbName(path), path });
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

  // Drei springende Punkte — sichtbar, dass gerechnet wird.
  const dots = document.createElement('div');
  dots.className = 'busy-dots';
  dots.setAttribute('aria-hidden', 'true');
  dots.innerHTML = '<i></i><i></i><i></i>';
  if (on) (hint ?? $('#lock-card h2'))?.after(dots);

  return () => {
    dots.remove();
    card?.removeAttribute('data-busy');
    $$('#lock-card button, #lock-card input').forEach(el => { el.disabled = false; });
    if (hint && before != null) hint.textContent = before;
  };
}

export async function lockDatabase() {
  if (vault.hasUnsavedChanges()) await vault.commit();
  await vault.lock();
  stopTicker();
  state.entries = [];
  state.strength.clear();
  state.codes.clear();
  state.pwned.clear();
  state.emailFindings = [];
  state.lastCheck = null;
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
