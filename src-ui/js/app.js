import * as vault from './data/vault.js';
import * as settings from './data/settings.js';
import { parseOtpauth, buildOtpauth } from './data/totp.js';
import { checkPwnedByHash, checkEmailBreached, breachAnalytics, accountDeletionIndex, findDeletion, passwordStrength as localStrength } from './data/security.js';
import { applyAppearance, applyTheme, applyPrimary, resolvedColor } from './core/theme.js';
import { avatarMarkup, hostFromUrl } from './core/icons.js';
import * as qr from './data/qr.js';
import * as preview from './data/preview.js';
import { enableDragMove } from './ui/dragmove.js';
import { parseImport, itemsFromCsv, CSV_FIELDS } from './data/import.js';
import * as pick from './ui/multiselect.js';
import { isTauri, isMobile, invoke, unlockMethods, pickDatabaseFile, pickSavePath, listen } from './core/platform.js';
import { dialog, banner, closeHostDialog, tableview, selectPicker, zurueckZu } from './ui/libs.js';
import { state, $, $$, esc, SECRET_MASK, VIEW_TITLES } from './core/state.js';
import { seite, nachLaden, renderAll, zeichne, refreshFromVault, nachStrukturaenderung } from './core/render.js';
import { copyPlain, scheduleClipboardClear } from './ui/clipboard.js';
import { captureFields, fieldChecked, pinStrengthNote, passwordField, wirePasswordFields } from './ui/formular.js';
import { renderTotp, tickTotp } from './pages/totp.js';
import { openFolderDialog } from './dialogs/folder.js';
import { renderPasswords, renderEntryTable, renderFiles, wireEntryRows, renderSelectionBar,
         showContextMenu, closeContextMenu, runRowAction, autoRetitle, adoptTitles,
         setupDragMove, openStoredFile, storedFiles, ensureTableview } from './pages/entries.js';
import { renderSecurity, countProblems, restoreCheck, runSecurityCheck, notify } from './pages/checkup.js';
import { showView } from './core/navigation.js';
import { renderTags, renderHome } from './pages/home.js';
import { openEntryDialog, openAttachmentViewer, scanWithCamera, bindFileDrops,
         showQrDialog, createEmptyFile, renderAttachments, addStagedAttachments } from './dialogs/entry.js';
import { loadAttachments, sizeOfDataUrl, formatBytes, downloadWithWarning, saveAttachment,
         generatePassword } from './data/attachments.js';
import { liveEntries, visibleEntries, expiryState, byId, hasFiles, isFileEntry,
         usageMap, markUsed, formatDate, zeitLabel, lastUsed } from './core/entries.js';


/* =========================================================
   Rendering
   ---------------------------------------------------------
   Die Reihenfolge hier ist die Reihenfolge beim Zeichnen.
   ========================================================= */
seite('schlagworte', renderTags);
seite('übersicht', renderHome);
seite('einträge', renderPasswords);
seite('totp', renderTotp);
seite('sicherheit', renderSecurity);
seite('einstellungen', renderSettings);
nachLaden(() => autoRetitle());

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

  // Lesen, Scrollen und Tippen rufen keinen Befehl im Kern auf — ohne diese
  // Meldung sperrte er mitten im Lesen. Höchstens alle 30 s.
  let lastTouch = 0;
  const activity = () => {
    if (state.locked || Date.now() - lastTouch < 30_000) return;
    lastTouch = Date.now();
    vault.touch().catch(() => {});
  };
  for (const type of ['pointerdown', 'keydown', 'wheel', 'touchmove']) {
    window.addEventListener(type, activity, { capture: true, passive: true });
  }

  // Abrufe über die Browser-Erweiterung zählen ebenfalls als Nutzung.
  await listen('entries-used', ev => markUsed(ev?.payload ?? []));

  // Android: Autofill und Passkeys schreiben in die offene Datenbank, ohne
  // dass die Oberfläche beteiligt ist. Danach die Liste nachziehen — und
  // wenn das Zurückschreiben scheitert, muss man es erfahren.
  await listen('vault-changed', async () => {
    if (state.locked) return;
    await refreshFromVault();
    renderAll({ ohne: ['einstellungen'] });
  });

  // Ein anderes Gerät hat in die Datei geschrieben, und der Kern hat den
  // Stand beim Speichern eingemischt — auch bei Browser und Autofill.
  await listen('vault-merged', () => takeForeign());

  // Fremde Änderungen holen: sobald die App wieder vorn ist, und jede
  // Minute, solange sie sichtbar ist. Ist die Datei unverändert, schaut der
  // Kern nur aufs Änderungsdatum.
  const syncNow = () => {
    if (!state.locked && document.visibilityState === 'visible') syncFromFile();
  };
  document.addEventListener('visibilitychange', syncNow);
  window.addEventListener('focus', syncNow);
  setInterval(syncNow, 60_000);

  await listen('autofill-saved', ev => {
    const n = Number(ev?.payload ?? 0);
    banner(n === 1 ? 'Ein Zugang aus dem Autofill wurde gespeichert.' : `${n} Zugänge aus dem Autofill wurden gespeichert.`, 'success', 5000);
  });
  await listen('save-failed', ev => {
    banner(`Änderung nicht gespeichert: ${ev?.payload ?? ''}`, 'error', 10000);
  });

  // Doppelklick auf eine .kdbx, während die App läuft (single-instance,
  // macOS: Ereignis des Systems): Sperrbildschirm für genau diese Datei.
  await listen('open-database', async ev => {
    const path = String(ev?.payload ?? '');
    if (!path) return;
    await vault.startupDatabase().catch(() => null);   // abholen, sonst käme sie beim nächsten Start nochmal
    if (!state.locked && path === settings.get('database.current', null)) return;
    if (!state.locked) await lockDatabase();
    await settings.set('database.current', path, { silent: true });
    await rememberDatabase({ name: dbName(path), path });
    state.unlock = await unlockMethods(path);
    renderLockscreen();
  });

  await bindOtpLinks();

  // Auswahlfelder bekommen das Aussehen der übrigen Oberfläche.
  selectPicker();

  await bindBrowserRequests();
  await bindFileDrops();
  bindStaticEvents();

  // Ändert sich die Auswahl, wird die Liste neu gezeichnet — dabei
  // erscheinen oder verschwinden die Kästchen.
  pick.onSelectionChange(() => {
    renderAll({ ohne: ['einstellungen'] });
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
  if (isMobile && !settings.get('android.setupSeen', false)) await showAndroidSetup();
  if (isTauri && !isMobile && !settings.get('browser.setupSeen', false)) await showBrowserSetupPage();
  renderLockscreen();

  // Ist die Datenbank an das Gerät gebunden (Windows Hello), wird gleich
  // gefragt — das ersetzt PIN und Master-Passwort. Nur beim Programmstart:
  // Nach einem Sperren von Hand soll nicht sofort wieder etwas aufgehen.
  if (state.unlock.device && settings.get('database.current', null)) unlock({ method: 'device' });
}

/**
 * otpauth://-Codes aus anderen Apps (Android: „Öffnen mit WKeePass" in der
 * Kamera-App). Über das Deep-Link-Plugin: beim Kaltstart liegt die Adresse
 * bereit, sonst kommt sie als Ereignis. Ist die Datenbank zu, wartet sie
 * bis nach dem Entsperren.
 */
async function bindOtpLinks() {
  if (!isTauri) return;
  const take = urls => {
    const uri = [urls].flat().map(String).find(u => /^otpauth(-migration)?:/i.test(u));
    if (!uri) return;
    if (state.locked) {
      state.pendingOtp = uri;
      banner('Entsperren — danach wird der Code übernommen.', 'info', 6000);
    } else {
      handleScan(uri);
    }
  };
  try { take(await invoke('plugin:deep-link|get_current') ?? []); } catch { /* Plugin fehlt */ }
  try { await listen('deep-link://new-url', ev => take(ev?.payload ?? [])); } catch { /* dito */ }
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
  await rememberDatabase({ name: dbName(path), path });
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
  // Auf Android und iOS gibt es die Browser-Erweiterung nicht.
  if (isMobile) return;

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





function recentDatabases() {
  const list = settings.get('database.recent', []);
  return Array.isArray(list) ? list : [];
}

async function rememberDatabase(entry) {
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
async function openUnlockDialog() {
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
function dbName(path) {
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

function pfadLabel(path, gemerkt = null) {
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
async function enterUnlocked() {
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

async function lockDatabase() {
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
    if (ev.target.closest('tr[data-id], tr.tv-group-row[data-folder]')) return;   // haben eigene Menüs
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

    ${state.locked ? '' : `<div class="settings-group" data-needs-db>
      <div class="section-label">Datenbank</div>
      <div class="settings-card">
        <div id="database-card">
          <div class="setting"><div class="setting-label"><small>Wird geladen …</small></div></div>
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
          <div class="setting-label"><strong>Warnen vor Ablauf</strong><small>Tage im Voraus</small></div>
          <div class="setting-control">
            <input type="number" min="1" max="180" data-set-db="expiryWarnDays" name="db.expiryWarnDays" value="${dbSettings.expiryWarnDays ?? 14}">
          </div>
        </div>
        <div class="setting">
          <div class="setting-label"><strong>Papierkorb leeren</strong><small>Entfernt die gelöschten Einträge endgültig</small></div>
          <div class="setting-control"><button type="button" class="button" id="btn-empty-bin">Leeren …</button></div>
        </div>
      </div>
    </div>`}

    <div class="settings-group">
      <div class="section-label">Entsperren</div>
      <div class="settings-card">
        <div class="setting">
          <div class="setting-label">
            <strong>Biometrie verwenden</strong>
            <small>${state.unlock.deviceAvailable
              ? `${esc(deviceName())} — beim Öffnen anbieten, ersetzt PIN und Master-Passwort`
              : state.unlock.biometricAvailable
                ? 'Fingerabdruck oder Gesichtserkennung'
                : 'Auf diesem Gerät nicht verfügbar'}</small>
          </div>
          <div class="setting-control"><input type="checkbox" data-shape="toggle" data-set="unlock.biometrics" name="unlock.biometrics" ${s.unlock?.biometrics ? 'checked' : ''} ${state.unlock.biometricAvailable || state.unlock.deviceAvailable ? '' : 'disabled'}></div>
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

    ${isMobile ? `<div class="settings-group">
      <div class="section-label">Android</div>
      <div class="settings-card" id="android-card">
        <div class="setting"><div class="setting-label"><small>Wird geladen …</small></div></div>
      </div>
    </div>` : ''}

    ${isMobile ? '' : `<div class="settings-group">
      <div class="section-label">Browser-Erweiterung</div>
      <div class="settings-card" id="browser-card">
        <div class="setting"><div class="setting-label"><small>Wird geladen …</small></div></div>
      </div>
    </div>`}

    <div class="settings-group">
      <div class="section-label">Einträge und Websites</div>
      <div class="settings-card">
        <div class="setting" data-needs-db>
          <div class="setting-label"><strong>Aus anderen Apps importieren</strong>
            <small>Passwörter und 2FA-Codes aus Bitwarden, 1Password, LastPass, Browsern, Aegis, 2FAS …</small></div>
          <div class="setting-control"><button type="button" class="button" id="btn-import-entries">Importieren …</button></div>
        </div>
        <div class="setting">
          <div class="setting-label">
            <strong>Icons der Websites laden</strong>
            <small>Einmal direkt von der jeweiligen Seite, ohne Sammeldienst — am besten beim Anmelden, wenn sie erreichbar ist.
              Danach liegt das Icon in der Datenbank und steht auch offline und auf allen Geräten bereit.</small>
          </div>
          <div class="setting-control"><input type="checkbox" data-shape="toggle" data-set="icons.download" name="icons.download" ${s.icons?.download ? 'checked' : ''}></div>
        </div>
        <div class="setting" data-needs-db>
          <div class="setting-label"><strong>Alle Icons neu abrufen</strong><small>Ersetzt die gespeicherten durch frisch geladene</small></div>
          <div class="setting-control"><button type="button" class="button" id="btn-refresh-icons"><span class="msr">refresh</span>&nbsp;Neu laden</button></div>
        </div>
        <div class="setting">
          <div class="setting-label"><strong>Namen von der Website</strong>
            <small>An: Steht als Name nur eine Adresse, heißt der Eintrag von selbst wie der Dienst —
              etwa „GitHub“ statt „https://github.com/login“. Selbst vergebene Namen bleiben.</small>
            <small data-needs-db>„Jetzt prüfen“ gleicht alle Einträge mit Adresse ab und ersetzt nach Rückfrage auch selbst vergebene Namen.</small></div>
          <div class="setting-control control-pair">
            <input type="checkbox" data-shape="toggle" data-set="names.fromWebsite" name="names.fromWebsite" ${s.names?.fromWebsite ?? true ? 'checked' : ''} aria-label="Namen automatisch setzen">
            <button type="button" class="button" id="btn-adopt-titles" data-needs-db><span class="msr">travel_explore</span>&nbsp;Jetzt prüfen</button>
          </div>
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
          <div class="setting-label"><strong>Bei neuen Funden benachrichtigen</strong><small>Wenn eine Prüfung ein neues Leck findet — auch bei der automatischen</small></div>
          <div class="setting-control"><input type="checkbox" data-shape="toggle" data-set="checks.notify" name="checks.notify" ${s.checks?.notify !== false ? 'checked' : ''}></div>
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
  renderDatabaseSection();
  renderAndroidSection($('#android-card'));
}

/* =========================================================
   Android: Passwortmanager, Passkeys, Kamera
   ---------------------------------------------------------
   Drei Freigaben, die nur der Nutzer erteilen kann — jeweils in einer
   anderen Ecke der Systemeinstellungen. Hier steht, was davon steht, und
   ein Knopf führt genau dorthin, wo es fehlt.
   ========================================================= */

const ANDROID_FREIGABEN = [
  { key: 'autofill', icon: 'password', title: 'Passwortmanager',
    text: 'Füllt Anmeldungen in Apps und im Browser aus und bietet an, neue Zugänge zu speichern.',
    action: 'Als Standard festlegen' },
  { key: 'passkeys', icon: 'passkey', title: 'Passkeys',
    text: 'Anmelden ohne Passwort. Die Passkeys liegen in deiner Datenbank, nicht bei Google.',
    action: 'Aktivieren', missing: 'Erst ab Android 14' },
  { key: 'kamera', icon: 'photo_camera', title: 'Kamera',
    text: 'Nur für den QR-Scanner: Zwei-Faktor-Codes einrichten, ohne das Geheimnis abzutippen.',
    action: 'Erlauben' }
];

/**
 * Zeichnet die drei Freigaben in `card`. Nach einem Klick fragt es eine
 * Weile nach — der Nutzer kommt aus den Systemeinstellungen zurück, ohne
 * dass die Seite davon erfährt.
 */
/**
 * Was passiert, bevor der Passwortmanager etwas in eine fremde App
 * einsetzt. Dieselben drei Stufen wie bei der Browser-Erweiterung — die
 * Auswahlliste kommt immer, herausgegeben wird erst danach.
 */
function ausfuellMarkup() {
  const guard = settings.get('android.guard', 'identify');
  const grace = Number(settings.get('android.graceSeconds', 60));

  return `
    <div class="setting">
      <div class="setting-label">
        <strong>Vor dem Ausfüllen</strong>
        <small>Was passiert, wenn du einen Zugang aus der Liste antippst:
        nichts, ein Knopfdruck oder ein Nachweis mit PIN, Master-Passwort oder Biometrie.</small>
      </div>
      <div class="setting-control">
        <div class="group-radio" id="android-guard">
          ${[['never', 'Nichts'], ['confirm', 'Bestätigen'], ['identify', 'Legitimieren']]
            .map(([value, label]) => `
              <label>
                <input type="radio" name="android.guard" value="${value}"
                  ${guard === value ? 'checked' : ''}>${label}
              </label>`).join('')}
        </div>
      </div>
    </div>
    <div class="setting">
      <div class="setting-label">
        <strong>Danach nicht erneut fragen</strong>
        <small>Wer gerade bestätigt oder entsperrt hat, wird so lange in Ruhe gelassen —
        ein Formular mit Name und Passwort fragt sonst zweimal.
        Gilt nicht bei „Nichts“; Sperren beendet die Frist sofort.</small>
      </div>
      <div class="setting-control">
        <select id="android-grace" name="android.graceSeconds" data-sp-picker data-sp-search="false">
          ${[[0, 'Jedes Mal fragen'], [30, '30 Sekunden'], [60, '1 Minute'], [300, '5 Minuten'], [900, '15 Minuten']]
            .map(([wert, label]) => `<option value="${wert}" ${grace === wert ? 'selected' : ''}>${label}</option>`).join('')}
        </select>
      </div>
    </div>`;
}

async function renderAndroidSection(card, { ausfuellen = true } = {}) {
  if (!card) return;
  let status;
  try { status = await vault.androidSetupStatus(); } catch { status = null; }

  // Die Stufe gilt auch dann, wenn die Freigaben gerade nicht zu erfragen
  // sind — sie steht deshalb vor ihnen und bleibt stehen. Beim ersten Start
  // geht es dagegen nur um die Freigaben; eingestellt wird später.
  card.innerHTML = ausfuellen ? ausfuellMarkup() : '';
  if (ausfuellen) wireAusfuellen(card);
  if (!status) return;

  card.insertAdjacentHTML('beforeend', ANDROID_FREIGABEN.map(f => {
    const s = status[f.key] ?? {};
    const control = s.aktiv
      ? `<span class="setting-state" data-tone="ok"><span class="msr">check_circle</span>Aktiv</span>`
      : !s.moeglich
        ? `<span class="setting-state">${esc(f.missing ?? 'Nicht verfügbar')}</span>`
        : `<button type="button" class="button hightlight" data-setup="${f.key}">
            ${s.gesperrt ? 'In App-Einstellungen erlauben' : esc(f.action)}</button>`;
    return `<div class="setting">
      <div class="setting-label"><strong><span class="msr">${f.icon}</span> ${esc(f.title)}</strong><small>${esc(f.text)}</small></div>
      <div class="setting-control">${control}</div>
    </div>`;
  }).join(''));

  card.querySelectorAll('[data-setup]').forEach(btn => btn.addEventListener('click', async () => {
    await vault.androidSetupOpen(btn.dataset.setup);
    watchAndroidSetup(card, JSON.stringify(status));
  }));
}

/** Stufe und Frist: Der Dienst liest beides bei jeder Anfrage neu. */
function wireAusfuellen(card) {
  card.querySelectorAll('[name="android.guard"]').forEach(el =>
    el.addEventListener('change', async () => {
      await settings.set('android.guard', el.value, { silent: true });
      banner({
        never: 'Zugänge werden ohne Rückfrage eingesetzt.',
        confirm: 'Ein Knopfdruck genügt — ohne Nachweis.',
        identify: 'PIN, Master-Passwort oder Biometrie vor dem Einsetzen.'
      }[el.value], el.value === 'never' ? 'warning' : 'success', 5000);
    }));

  card.querySelector('#android-grace')?.addEventListener('change', async ev => {
    await settings.set('android.graceSeconds', Number(ev.target.value), { silent: true });
  });
}

/** Fragt eine Minute lang jede Sekunde nach und zeichnet bei Änderung neu. */
function watchAndroidSetup(card, before) {
  clearInterval(card._watch);
  let rounds = 0;
  card._watch = setInterval(async () => {
    if (++rounds > 60 || !card.isConnected) { clearInterval(card._watch); return; }
    const now = await vault.androidSetupStatus().catch(() => null);
    if (now && JSON.stringify(now) !== before) {
      clearInterval(card._watch);
      renderAndroidSection(card);
    }
  }, 1000);
}

/**
 * Beim ersten Start auf Android: sagen, wozu die Freigaben gut sind, und
 * sie gleich einrichten lassen. Überspringen geht jederzeit — alles steht
 * danach auch in den Einstellungen.
 */
async function showAndroidSetup() {
  return new Promise(resolve => {
    $('#welcome').hidden = false;
    $('#welcome-card').innerHTML = `
      ${BRAND_MARK}
      <h2>Drei Freigaben für den Alltag</h2>
      <p class="lock-sub">Damit WKeePass nicht nur Tresor ist, sondern dir beim Anmelden hilft, braucht es die Erlaubnis von Android.
        Nichts davon schickt Daten irgendwohin — die Passwörter bleiben in deiner Datei.</p>
      <div class="settings-card" id="android-setup"></div>
      <div class="lock-actions">
        <button type="button" class="button hightlight" data-shape="full" id="as-done"><span class="msr">check</span>&nbsp;Weiter</button>
        <button type="button" class="button" data-shape="full" id="as-later">Später in den Einstellungen</button>
      </div>`;

    renderAndroidSection($('#android-setup'), { ausfuellen: false });

    const done = async () => {
      clearInterval($('#android-setup')?._watch);
      await settings.set('android.setupSeen', true, { silent: true });
      $('#welcome').hidden = true;
      resolve();
    };
    $('#as-done').onclick = done;
    $('#as-later').onclick = done;
  });
}

/** Die drei Stufen der Schlüsselableitung, wie sie der Kern kennt. */
/** Die Stufen des Kerns (database.rs): Durchgänge und Speicher je Stufe. */
const STUFEN = [
  ['schnell', 'Schnell', 'Öffnet zügig, auch auf älteren Geräten', 5, 32],
  ['standard', 'Standard', 'Guter Mittelweg — Empfehlung', 10, 64],
  ['stark', 'Stark', 'Bestmöglicher Schutz, spürbar längeres Öffnen', 20, 256]
];

/**
 * Welche Stufe einer eigenen Einstellung am nächsten kommt. Der Aufwand
 * wächst mit Durchgängen mal Speicher; verglichen wird logarithmisch, weil
 * die Stufen jeweils ein Vielfaches auseinanderliegen.
 */
function naechsteStufe(iterations, memoryMib) {
  const aufwand = Math.log(Math.max(1, iterations * memoryMib));
  let beste = 0;
  STUFEN.forEach(([, , , it, mem], i) => {
    if (Math.abs(Math.log(it * mem) - aufwand) < Math.abs(Math.log(STUFEN[beste][3] * STUFEN[beste][4]) - aufwand)) beste = i;
  });
  return beste;
}

/**
 * Name und Verschlüsselung der offenen Datenbank.
 *
 * Der Name steht in der Datei selbst, nicht im Dateinamen — er erscheint
 * überall dort, wo die Datenbank auftaucht, und ist auf dem Handy oft die
 * einzige Bezeichnung, die es gibt.
 */
async function renderDatabaseSection() {
  const card = $('#database-card');
  if (!card) return;

  // Solange am Regler eine Auswahl offen ist oder gerade geschrieben wird,
  // bleibt der Abschnitt stehen. Neu gezeichnet risse er den Regler unter
  // dem Finger weg — genau das Flackern, das hier nicht sein darf.
  if (card.dataset.offen) return;

  let info;
  try {
    info = await vault.security();
  } catch (err) {
    card.innerHTML = `<div class="setting"><div class="setting-label">
      <strong>Nicht verfügbar</strong><small>${esc(err.message)}</small></div></div>`;
    return;
  }

  const path = settings.get('database.current', null);
  const eintrag = recentDatabases().find(d => d.path === path);
  let eigen = info.level === 'eigen';
  let stufe = eigen
    ? naechsteStufe(info.iterations, info.memoryMib)
    : Math.max(0, STUFEN.findIndex(([wert]) => wert === info.level));
  const hinweis = i => eigen && i === stufe && Number(regler?.value ?? stufe) === stufe
    ? `Eigene Einstellung — liegt etwa bei „${STUFEN[i][1]}“. Verschieben ersetzt sie.`
    : STUFEN[i][2];
  let regler = null;

  card.innerHTML = `
    <div class="setting">
      <div class="setting-label">
        <strong>Name der Datenbank</strong>
        <small>Steht in der Datei, nicht im Dateinamen${path ? ` · ${esc(pfadLabel(path, eintrag?.label))}` : ''}</small>
      </div>
      <div class="setting-control">
        <input type="text" id="db-name" value="${esc(info.name)}" placeholder="Passwörter"
               ${info.readOnly ? 'disabled' : ''}>
      </div>
    </div>

    <div class="setting" data-stacked>
      <div class="setting-label">
        <strong>Verschlüsselungsstärke</strong>
        <small>Wie lange das Ableiten des Schlüssels dauert — für dich einmal beim Öffnen,
        für einen Angreifer bei jedem Rateversuch</small>
      </div>
      <div class="setting-control kdf-slider">
        <input type="range" id="db-level" min="0" max="${STUFEN.length - 1}" step="1" value="${stufe}"
               aria-label="Verschlüsselungsstärke" ${info.readOnly ? 'disabled' : ''}>
        <div class="kdf-labels">
          ${STUFEN.map(([, name], i) => `<button type="button" data-stufe="${i}" ${i === stufe ? 'aria-current="true"' : ''}
            ${info.readOnly ? 'disabled' : ''}>${name}</button>`).join('')}
        </div>
        <small class="kdf-note" id="db-level-note"></small>
        <div class="kdf-apply" id="db-level-apply" hidden>
          <button type="button" class="button" id="db-level-undo">Zurück</button>
          <button type="button" class="button hightlight" id="db-level-ok">Übernehmen</button>
        </div>
      </div>
    </div>

    <div class="setting">
      <div class="setting-label">
        <strong>Versionen</strong>
        <small>Die letzten Stände dieser Datei — beim Öffnen, nach dem Speichern und nach
        Änderungen von einem anderen Gerät. Daraus lässt sich Einzelnes oder alles zurückholen.</small>
      </div>
      <div class="setting-control">
        <button type="button" class="button" id="btn-versions">Versionen ansehen …</button>
      </div>
    </div>

    <div class="setting">
      <div class="setting-label">
        <strong>Im Einzelnen</strong>
        <small id="db-details">${esc(info.format)} · ${esc(info.cipher)} · ${esc(info.kdf)}
        mit ${info.iterations} Durchgängen, ${info.memoryMib} MiB, ${info.parallelism} Fäden</small>
        <small id="db-modified" hidden></small>
      </div>
    </div>`;

  card.querySelector('#btn-versions')?.addEventListener('click', () => openVersionsDialog());

  const speichern = async (feld, wert) => {
    try {
      await vault.setSecurity(wert);
      banner(feld === 'name' ? 'Name gespeichert.' : 'Verschlüsselung geändert — die Datei wurde neu geschrieben.', 'success');
      renderDatabaseSection();
    } catch (err) {
      banner(`Nicht gespeichert: ${err.message}`, 'error', 6000);
    }
  };

  const name = card.querySelector('#db-name');
  name?.addEventListener('change', () => {
    if (name.value.trim() !== info.name) speichern('name', { name: name.value.trim() });
  });

  /* Der Schieberegler.

     Ziehen wählt nur aus. Geschrieben wird erst mit „Übernehmen" — jede
     Änderung verschlüsselt die ganze Datei neu, und das dauert Sekunden.

     Vorher schrieb der Regler von selbst, eine halbe Sekunde nach der
     letzten Bewegung. Das ging auf dem Handy gründlich schief: Der
     Webview meldet schon während des Ziehens, jede kurze Pause löste eine
     Neuverschlüsselung aus, die Ladeanzeige legte sich über den Regler,
     und bei einer eigenen Einstellung kam jedes Mal die Rückfrage. Jetzt
     hängt am Regler nichts mehr, was etwas auslöst. */
  regler = card.querySelector('#db-level');
  const note = card.querySelector('#db-level-note');
  const einzeln = card.querySelector('#db-details');
  const zeile = card.querySelector('#db-level-apply');
  const ok = card.querySelector('#db-level-ok');
  const undo = card.querySelector('#db-level-undo');

  // Eine eigene Einstellung liegt auf keiner Stufe. Erst wenn der Regler
  // angefasst wurde, gilt seine Stellung als Wunsch.
  let beruehrt = false;
  const offen = () => beruehrt && (eigen || Number(regler.value) !== stufe);

  const zeige = () => {
    const i = Number(regler.value);
    note.textContent = offen() && eigen
      ? `Ersetzt die eigene Einstellung (${info.iterations} Durchgänge, ${info.memoryMib} MiB) durch „${STUFEN[i][1]}“.`
      : hinweis(i);
    card.querySelectorAll('[data-stufe]').forEach(b =>
      b.toggleAttribute('aria-current', Number(b.dataset.stufe) === i));
    zeile.hidden = !offen();
    // Der Abschnitt bleibt stehen, solange hier etwas offen ist.
    if (offen()) card.dataset.offen = '1'; else delete card.dataset.offen;
  };

  const waehle = wert => {
    if (wert !== undefined) regler.value = wert;
    beruehrt = true;
    zeige();
  };

  regler?.addEventListener('input', () => waehle());
  card.querySelectorAll('[data-stufe]').forEach(b =>
    b.addEventListener('click', () => waehle(b.dataset.stufe)));

  undo?.addEventListener('click', () => {
    regler.value = stufe;
    beruehrt = false;
    zeige();
  });

  ok?.addEventListener('click', async () => {
    const i = Number(regler.value);
    ok.disabled = true;
    undo.disabled = true;
    try {
      await vault.setSecurity({ level: STUFEN[i][0] });
      eigen = false;
      stufe = i;
      beruehrt = false;
      info = await vault.security();
      if (einzeln) {
        einzeln.textContent = `${info.format} · ${info.cipher} · ${info.kdf} mit ${info.iterations} Durchgängen, ${info.memoryMib} MiB, ${info.parallelism} Fäden`;
      }
      banner('Verschlüsselung geändert — die Datei wurde neu geschrieben.', 'success');
    } catch (err) {
      banner(`Nicht gespeichert: ${err.message}`, 'error', 6000);
    } finally {
      ok.disabled = false;
      undo.disabled = false;
      zeige();
    }
  });

  zeige();

  // Änderungsdatum der Datei — fragt je nach Ort das Dateisystem oder den
  // Cloud-Anbieter, darum nachgereicht statt beim Zeichnen.
  const modifiedEl = card.querySelector('#db-modified');
  if (path && modifiedEl) {
    invoke('database_modified', { path }).then(ms => {
      if (!ms) return;
      modifiedEl.textContent = `Datei zuletzt geändert: ${new Date(ms).toLocaleString('de-DE', { dateStyle: 'medium', timeStyle: 'short' })}`;
      modifiedEl.hidden = false;
    }).catch(() => {});
  }
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
  const grace = Number(settings.get('browser.graceSeconds', 60));

  card.innerHTML = `
    <div class="setting">
      <div class="setting-label">
        <strong>Vor dem Ausfüllen</strong>
        <small>Was passiert, wenn ein verknüpfter Browser Zugangsdaten anfragt:
        nichts, ein Knopfdruck oder ein Nachweis mit PIN, Master-Passwort oder Fingerabdruck.</small>
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
        <strong>Danach nicht erneut fragen</strong>
        <small>Wer gerade bestätigt oder entsperrt hat, wird so lange in Ruhe gelassen —
        eine Anmeldung mit mehreren Feldern fragt sonst mehrmals. Danach wird wieder gefragt.
        Gilt nicht bei „Nichts“; Sperren beendet die Frist sofort.</small>
      </div>
      <div class="setting-control">
        <select id="browser-grace" name="browser.graceSeconds" data-sp-picker data-sp-search="false">
          ${[[0, 'Jedes Mal fragen'], [30, '30 Sekunden'], [60, '1 Minute'], [300, '5 Minuten'], [900, '15 Minuten']]
            .map(([wert, label]) => `<option value="${wert}" ${grace === wert ? 'selected' : ''}>${label}</option>`).join('')}
        </select>
      </div>
    </div>
    <div class="setting" data-stacked>
      <div class="setting-label">
        <strong>Erweiterung</strong>
        <small>KeePassXC-Browser — WKeePass spricht dasselbe Protokoll, deshalb gibt es keine eigene.</small>
      </div>
      <div class="setting-control store-buttons">
        ${BROWSER_STORES.map((b, i) => `<button type="button" class="button" data-store="${i}"><span class="msr">open_in_new</span>&nbsp;${esc(b.name)}</button>`).join('')}
      </div>
    </div>
    <div class="setting">
      <div class="setting-label">
        <strong>Eingetragen bei</strong>
        <small>${esc(eingerichtet)}</small>
        <small>„Einrichten“ legt je Browser eine Datei ab, die auf WKeePass zeigt — ohne sie darf der Browser WKeePass nicht starten.</small>
      </div>
      <div class="setting-control">
        <button type="button" class="button" id="btn-browser-install">Einrichten</button>
        <button type="button" class="button" id="btn-browser-remove">Entfernen</button>
      </div>
    </div>
    ${verknuepft}
    <div class="setting">
      <div class="setting-label">
        <strong>Kanal</strong>
        <small>${status.listening ? 'Aktiv' : 'Nicht aktiv'} — <code>${esc(status.socket)}</code></small>
      </div>
    </div>`;

  card.querySelectorAll('[name="browser.guard"]').forEach(el =>
    el.addEventListener('change', async () => {
      await settings.set('browser.guard', el.value, { silent: true });
      banner({
        never: 'Verknüpfte Browser füllen ohne Rückfrage aus.',
        confirm: 'Ein Knopfdruck genügt — ohne Nachweis.',
        identify: 'PIN, Master-Passwort oder Fingerabdruck vor dem Ausfüllen.'
      }[el.value], el.value === 'never' ? 'warning' : 'success', 5000);
    }));

  // Der Kern liest die Frist bei jeder Anfrage aus den Einstellungen.
  card.querySelector('#browser-grace')?.addEventListener('change', async ev => {
    await settings.set('browser.graceSeconds', Number(ev.target.value), { silent: true });
  });

  card.querySelector('#btn-browser-install')?.addEventListener('click', () => browserSetup(true));
  card.querySelectorAll('[data-store]').forEach(btn => btn.addEventListener('click', () =>
    vault.openLink(BROWSER_STORES[btn.dataset.store].url).catch(err => banner(err.message, 'error', 6000))));
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
/** Wo es keepassxc-browser gibt — WKeePass spricht dasselbe Protokoll. */
const BROWSER_STORES = [
  { name: 'Firefox', url: 'https://addons.mozilla.org/firefox/addon/keepassxc-browser/' },
  { name: 'Chrome, Brave, Vivaldi', url: 'https://chromewebstore.google.com/detail/keepassxc-browser/oboonakemofpalcgghocfoadofidjkkk' },
  { name: 'Edge', url: 'https://microsoftedge.microsoft.com/addons/detail/keepassxcbrowser/pdffhmdngciaglkoonimfcmckehcpafo' }
];

/**
 * Beim ersten Start am Rechner: die Browser-Erweiterung vorstellen und
 * gleich einrichten lassen. Drei Schritte — bei den Browsern eintragen,
 * Erweiterung installieren, im Browser verbinden. Überspringen geht; alles
 * steht danach auch in den Einstellungen.
 */
async function showBrowserSetupPage() {
  return new Promise(resolve => {
    $('#welcome').hidden = false;
    const card = $('#welcome-card');

    const render = async () => {
      let status = null;
      try { status = await vault.browserStatus(); } catch { /* ohne Stand weiter */ }
      const found = status ? [...status.installed, ...status.available] : [];
      const done = status?.installed ?? [];

      card.innerHTML = `
        ${BRAND_MARK}
        <h2>Passwörter direkt im Browser</h2>
        <p class="lock-sub">Mit einer Browser-Erweiterung füllt WKeePass Anmeldungen auf Webseiten aus,
          bietet neue Zugänge zum Speichern an und meldet dich mit Passkeys an. Die Passwörter bleiben in deiner Datei —
          der Browser fragt jedes Mal bei WKeePass nach. Dafür braucht es alle drei Schritte.</p>

        <div class="settings-card">
          <div class="setting">
            <div class="setting-label"><strong>1. WKeePass bei den Browsern anmelden</strong>
              <small>Notwendig: Ein Browser darf nur Programme starten, die bei ihm eingetragen sind. Der Knopf legt dafür
                je Browser eine kleine Datei ab, die auf WKeePass zeigt — am Browser selbst ändert sich nichts.
                Ist KeePassXC installiert, spricht die Erweiterung danach mit WKeePass statt mit KeePassXC.</small>
              <small>${found.length
                ? `Gefunden: ${found.map(b => `${esc(b)}${done.includes(b) ? ' ✓' : ''}`).join(' · ')}`
                : 'Kein Browser gefunden — nach der Installation eines Browsers geht das in den Einstellungen.'}</small></div>
            <div class="setting-control">${found.length && done.length === found.length
              ? `<span class="setting-state" data-tone="ok"><span class="msr">check_circle</span>Erledigt</span>`
              : `<button type="button" class="button hightlight" id="bs-install" ${found.length ? '' : 'disabled'}>Eintragen</button>`}</div>
          </div>
          <div class="setting" data-stacked>
            <div class="setting-label"><strong>2. Erweiterung KeePassXC-Browser installieren</strong>
              <small>Notwendig: Die Erweiterung stammt von KeePassXC und ist kostenlos. WKeePass spricht dieselbe Sprache,
                deshalb gibt es keine eigene. Der Knopf öffnet die Seite im Store deines Browsers.</small></div>
            <div class="setting-control store-buttons">
              ${BROWSER_STORES.map((b, i) => `<button type="button" class="button" data-store="${i}"><span class="msr">open_in_new</span>&nbsp;${esc(b.name)}</button>`).join('')}
            </div>
          </div>
          <div class="setting">
            <div class="setting-label"><strong>3. Im Browser verbinden</strong>
              <small>Einmal je Browser: Browser neu starten, auf das Symbol der Erweiterung klicken und „Verbinden“ wählen.
                WKeePass fragt dann nach einem Namen für diesen Browser — erst danach werden Passwörter ausgefüllt.</small></div>
          </div>
        </div>

        <div class="lock-actions">
          <button type="button" class="button hightlight" data-shape="full" id="bs-done"><span class="msr">check</span>&nbsp;Weiter</button>
          <button type="button" class="button" data-shape="full" id="bs-later">Später in den Einstellungen</button>
        </div>`;

      card.querySelector('#bs-install')?.addEventListener('click', async () => {
        await browserSetup(true);
        render();
      });
      card.querySelectorAll('[data-store]').forEach(btn => btn.addEventListener('click', () =>
        vault.openLink(BROWSER_STORES[btn.dataset.store].url).catch(err => banner(err.message, 'error', 6000))));

      const finish = async () => {
        await settings.set('browser.setupSeen', true, { silent: true });
        $('#welcome').hidden = true;
        resolve();
      };
      card.querySelector('#bs-done').onclick = finish;
      card.querySelector('#bs-later').onclick = finish;
    };

    render();
  });
}

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
    if (el.dataset.set === 'names.fromWebsite' && value) autoRetitle();

    banner('Einstellung gespeichert.', 'success', 1600);
  }));

  root.querySelectorAll('[name="checks.automatic"]').forEach(el =>
    el.addEventListener('change', async () => {
      await settings.set('checks.automatic', el.value, { silent: true });
      updateSettingsPreview();
    }));

  root.querySelector('#btn-refresh-icons')?.addEventListener('click', async () => {
    await vault.fetchIcons(null, true);
    banner('Icons werden neu abgerufen — sie erscheinen, sobald sie da sind.', 'success');
  });

  root.querySelector('#btn-adopt-titles')?.addEventListener('click', async () => {
    const withUrl = state.entries.filter(e => hostFromUrl(e.url));
    if (!withUrl.length) { banner('Kein Eintrag hat eine URL.', 'info'); return; }

    const res = await dialog({
      title: 'Namen übernehmen',
      content: `Bei <strong>${withUrl.length}</strong> Einträgen wird der Name durch den Namen des Dienstes ersetzt.
                ${isTauri ? '' : '<br><br>Im Browser blockiert die Sicherheitsrichtlinie fremder Seiten den Abruf — dort wird ersatzweise der Hostname verwendet.'}`,
      confirmText: 'Übernehmen',
      cancelText: 'Abbrechen'
    });
    if (!(res?.submit ?? res)) return;
    await adoptTitles(withUrl);
  });

  root.querySelector('#btn-import-entries')?.addEventListener('click', () => importFromOtherApps());

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
    renderAll({ ohne: ['einstellungen'] });
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

/* =========================================================
   Versionen
   ---------------------------------------------------------
   Der Kern hebt die letzten Stände der Datei auf. Hier stehen zwei
   Dialoge: die Liste der Stände und, dahinter, was sich seit einem davon
   geändert hat. Zurückgeholt wird einzeln oder in einem Rutsch; geschrieben
   wird erst danach, mit demselben `commit` wie bei jeder anderen Änderung.
   ========================================================= */



async function openVersionsDialog() {
  let staende = [];
  try {
    staende = await vault.versions();
  } catch (err) {
    banner(`Versionen nicht lesbar: ${err.message}`, 'error', 6000);
    return;
  }

  if (!staende.length) {
    banner('Noch keine Stände — der erste entsteht beim nächsten Öffnen oder Speichern.', 'info', 5000);
    return;
  }

  await dialog({
    title: 'Versionen',
    content: `
      <p class="dlg-note">Jeder Stand ist die vollständige Datei, verschlüsselt wie das Original.
      Tippe einen an, um zu sehen, was sich seitdem geändert hat.</p>
      <div class="version-list">
        ${staende.map(v => `
          <button type="button" class="version-row" data-version="${esc(v.id)}">
            <span class="version-time">${esc(zeitLabel(v.at))}</span>
            <span class="version-reason">${esc(v.reason)}</span>
            <span class="msr">chevron_right</span>
          </button>`).join('')}
      </div>`,
    // Ohne Bestätigungsknopf fällt die Fußzeile weg — eine Liste braucht
    // keine.
    confirmText: null,
    cancelText: 'Schließen',
    // Ohne Fußzeile führt nur das Kreuz oben heraus.
    barRight: { icon: 'close', title: 'Schließen', action: 'cancel' },
    // `onInsert` bekommt die Kennung, nicht das Element — der Dialog steht
    // zu diesem Zeitpunkt schon im Dokument.
    onInsert: id => {
      const host = document.getElementById(String(id));
      host?.querySelectorAll('[data-version]').forEach(btn => btn.addEventListener('click', () => {
        const stand = staende.find(v => v.id === btn.dataset.version);
        closeHostDialog(btn, false);
        setTimeout(() => openVersionChangesDialog(stand), 50);
      }));
    }
  });
}

async function openVersionChangesDialog(stand) {
  if (!stand) return;

  let changes;
  try {
    changes = await vault.versionChanges(stand.id);
  } catch (err) {
    banner(`Der Stand ließ sich nicht vergleichen: ${err.message}`, 'error', 6000);
    return;
  }

  const ART = {
    neu: ['Dazugekommen', 'add_circle'],
    geloescht: ['Verschwunden', 'remove_circle'],
    geaendert: ['Geändert', 'edit']
  };

  const inhalt = changes.length
    ? `<div class="version-changes">
        ${changes.map(c => {
          const [label, icon] = ART[c.kind] ?? ART.geaendert;
          const felder = c.fields.map(f => f.before == null && f.after == null
            ? `<li>${esc(f.name)} geändert</li>`
            : `<li>${esc(f.name)}: <del>${esc(f.before || '—')}</del> <span class="msr">arrow_forward</span> ${esc(f.after || '—')}</li>`).join('');
          return `<div class="version-change" data-kind="${c.kind}">
            <div class="version-change-head">
              <span class="msr">${icon}</span>
              <strong>${esc(c.name || '(ohne Titel)')}</strong>
              <small>${esc(label)}${c.folder ? ` · ${esc(c.folder)}` : ''}</small>
              <button type="button" class="button" data-undo="${esc(c.id)}">Zurücknehmen</button>
            </div>
            ${felder ? `<ul class="version-fields">${felder}</ul>` : ''}
          </div>`;
        }).join('')}
      </div>`
    : '<p class="dlg-note">Seit diesem Stand hat sich nichts geändert.</p>';

  await dialog({
    title: `Stand ${zeitLabel(stand.at)}`,
    // Oben links „Zurück": von einem Stand wieder in die Liste, ohne über
    // die Einstellungen zu laufen.
    onBack: zurueckZu(openVersionsDialog),
    content: `
      <p class="dlg-note">${esc(stand.reason)} · Was hier steht, ist der Unterschied zum jetzigen Stand.
      Zurückgeholtes wird erst geschrieben, wenn du danach speicherst — das macht die App gleich selbst.</p>
      ${inhalt}`,
    confirmText: changes.length ? 'Alles zurückholen' : null,
    cancelText: 'Schließen',
    // Gibt es nichts zurückzuholen, fehlt die Fußzeile — dann das Kreuz.
    barRight: changes.length ? null : { icon: 'close', title: 'Schließen', action: 'cancel' },
    onInsert: id => {
      const host = document.getElementById(String(id));
      host?.querySelectorAll('[data-undo]').forEach(btn => btn.addEventListener('click', async () => {
        btn.disabled = true;
        await zurueckholen(stand.id, [btn.dataset.undo]);
        btn.closest('.version-change')?.remove();
      }));
    }
  }).then(res => {
    if (res?.submit ?? res) return zurueckholen(stand.id, null);
  });
}

/** Holt zurück und schreibt die Datei. */
async function zurueckholen(id, entries) {
  try {
    const zahl = await vault.versionRestore(id, entries);
    await vault.commit();
    await refreshFromVault();
    renderAll({ ohne: ['einstellungen'] });
    banner(entries
      ? 'Eintrag zurückgeholt und gespeichert.'
      : `${zahl} Eintr${zahl === 1 ? 'ag' : 'äge'} zurückgeholt und gespeichert.`, 'success');
  } catch (err) {
    banner(`Zurückholen fehlgeschlagen: ${err.message}`, 'error', 6000);
  }
}







async function startCreation() {
  const scannable = qr.scannerAvailable();

  await dialog({
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
        <button type="button" class="choice" data-choice="import">
          <span class="msr">download</span>
          <strong>Importieren</strong>
          <small>Passwörter und 2FA-Codes aus anderen Apps übernehmen</small>
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
    // Nur eine Auswahl: Jede Kachel ist schon die Entscheidung, also keine
    // Fußzeile.
    confirmText: null,
    cancelText: 'Abbrechen',
    // Ohne Fußzeile führt nur das Kreuz oben heraus.
    barRight: { icon: 'close', title: 'Abbrechen', action: 'cancel' },
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

  // Jeder Weg von hier aus trägt den Rückweg mit: oben links ein Pfeil
  // zurück in diese Auswahl.
  if (choice === 'manual') { openEntryDialog(null, {}, { zurueck: startCreation }); return; }
  if (choice === 'files') { openEntryDialog(null, {}, { mode: 'files', zurueck: startCreation }); return; }
  if (choice === 'folder') { openFolderDialog({ zurueck: startCreation }); return; }
  if (choice === 'import') { importFromOtherApps({ zurueck: startCreation }); return; }

  try {
    const value = choice === 'camera' ? await scanWithCamera({ zurueck: startCreation }) : await scanFromFile();
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

  // Kein vorhandener Eintrag passt zum Aussteller? Dann gibt es nichts zu
  // wählen — gleich den neuen Eintrag öffnen, vorausgefüllt.
  const config0 = { digits: parsed.digits, period: parsed.period, algorithm: parsed.algorithm };
  if (!suggestion || suggestion.hasTotp) {
    openEntryDialog(null, {
      name: parsed.issuer || parsed.name,
      username: parsed.name,
      totpSecret: parsed.secret,
      totpConfig: config0
    });
    return;
  }

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
          <select id="totp-target" data-sp-picker>
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
    renderAll({ ohne: ['einstellungen'] });
    banner(`TOTP zu „${entry.name}“ hinzugefügt.`, 'success');
    // Gleich zeigen, wo er gelandet ist.
    openEntryDialog(entry.id);
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
  renderAll({ ohne: ['einstellungen'] });

  const skipped = accounts.length - created;
  banner(`${created} Einträge angelegt${skipped ? `, ${skipped} übersprungen (kein TOTP)` : ''}.`, 'success', 5000);
}

/* =========================================================
   Import aus anderen Programmen (Formate: siehe import.js)
   ========================================================= */

function pickFile(accept) {
  return new Promise(resolve => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = accept;
    input.addEventListener('change', () => resolve(input.files?.[0] ?? null));
    input.click();
  });
}

async function importFromOtherApps({ zurueck = null } = {}) {
  if (state.locked) { banner('Erst die Datenbank entsperren.', 'info'); return; }

  const file = await pickFile('.csv,.json,.txt,.2fas,.xml,.zip,text/csv,application/json,text/plain,text/xml,application/zip');
  if (!file) return;

  let result;
  try { result = await parseImport(file); }
  catch (err) { banner(`Import nicht möglich: ${err.message}`, 'error', 8000); return; }

  // Was es schon gibt (gleicher Name, Benutzer und Adresse), wird ausgelassen —
  // so schadet es nicht, denselben Export zweimal einzulesen.
  const key = e => [e.name, e.username, e.url].map(v => String(v ?? '').trim().toLowerCase()).join('\u0001');
  const known = new Set(state.entries.map(key));
  const folder = `Importiert/${result.source.replace(/\//g, '-')}`;

  let items = result.items;
  let fresh = [];
  let dupes = 0;
  const count = () => {
    fresh = items.filter(i => !known.has(key(i)));
    dupes = items.length - fresh.length;
  };
  count();

  // Bei CSV lässt sich festlegen, welche Spalte was bedeutet. Ohne erkannte
  // Passwort- oder 2FA-Spalte ist die Zuordnung gleich aufgeklappt.
  const csv = result.csv;
  const mapping = csv ? [...csv.mapping] : null;
  const needsMapping = csv && !mapping.some(f => f === 'password' || f === 'totp');

  if (!csv && !fresh.length) {
    banner(`Alle ${items.length} Einträge aus ${result.source} sind schon vorhanden.`, 'info', 6000);
    return;
  }

  const summary = () => {
    if (!items.length) {
      return `<p class="dlg-note">Noch keine Einträge — ordne unten mindestens Passwort, Benutzername, Adresse oder 2FA-Schlüssel einer Spalte zu.</p>`;
    }
    const withPw = fresh.filter(i => i.password).length;
    const withTotp = fresh.filter(i => i.totp).length;
    return `
      <p class="dlg-note"><strong>${fresh.length}</strong> Einträge — ${withPw} mit Passwort, ${withTotp} mit 2FA-Code${
        dupes ? `, ${dupes} schon vorhanden und ausgelassen` : ''}. Sie landen im Ordner <strong>${esc(folder)}</strong>.</p>
      <ul class="import-list">
        ${fresh.slice(0, 200).map(i => `<li><strong>${esc(i.name)}</strong><span>${esc(i.username)}${
          i.totp ? ' · <span class="msr" title="2FA-Code">timer</span>' : ''}</span></li>`).join('')}
        ${fresh.length > 200 ? `<li><span>… und ${fresh.length - 200} weitere</span></li>` : ''}
      </ul>`;
  };

  // Beispielwert je Spalte — Passwörter und 2FA-Schlüssel nur als Punkte.
  const sample = i => {
    const v = csv.rows.map(r => (r[i] ?? '').trim()).find(Boolean) ?? '';
    if (!v) return '—';
    if (mapping[i] === 'password' || mapping[i] === 'totp') return '••••••';
    return v.length > 40 ? `${v.slice(0, 40)}…` : v;
  };
  const columns = csv ? `
      <details class="import-mapping" ${needsMapping ? 'open' : ''}>
        <summary>Spalten zuordnen</summary>
        <div class="import-columns">
          ${csv.header.map((h, i) => `
            <div class="import-column">
              <span><strong>${esc(h || `Spalte ${i + 1}`)}</strong><small data-sample="${i}">${esc(sample(i))}</small></span>
              <select data-col="${i}" data-sp-picker data-sp-search="false" aria-label="${esc(h || `Spalte ${i + 1}`)}">
                ${CSV_FIELDS.map(([v, label]) => `<option value="${v}" ${mapping[i] === v ? 'selected' : ''}>${esc(label)}</option>`).join('')}
              </select>
            </div>`).join('')}
        </div>
      </details>` : '';

  const confirmLabel = () => (fresh.length ? `${fresh.length} Einträge importieren` : 'Importieren');

  const res = await dialog({
    title: `Import aus ${esc(result.source)}`,
    content: `
      <div id="import-summary">${summary()}</div>
      ${columns}
      <p class="dlg-note"><small>Die Exportdatei enthält alles im Klartext — danach am besten löschen.</small></p>`,
    confirmText: confirmLabel(),
    cancelText: 'Abbrechen',
    onBack: zurueckZu(zurueck),
    onInsert: id => {
      const host = document.getElementById(String(id));
      const submit = host?.querySelector('.dialog_submit');
      if (submit) submit.disabled = !fresh.length;
      host?.querySelectorAll('select[data-col]').forEach(sel => sel.addEventListener('change', () => {
        const i = Number(sel.dataset.col);
        mapping[i] = sel.value;
        items = itemsFromCsv(csv, mapping);
        count();
        host.querySelector('#import-summary').innerHTML = summary();
        host.querySelector(`[data-sample="${i}"]`).textContent = sample(i);
        if (submit) {
          submit.textContent = confirmLabel();
          submit.disabled = !fresh.length;
        }
      }));
    }
  });
  if (!(res?.submit ?? res) || !fresh.length) return;

  let created = 0;
  const failed = [];
  for (const i of fresh) {
    try {
      const passwordToken = i.password ? await vault.setSecret(null, i.password) : null;
      const totpToken = i.totp ? await vault.setSecret(null, i.totp.secret) : null;
      await vault.saveEntry({
        id: null,
        name: i.name,
        folder: i.folder ? `${folder}/${i.folder.replace(/^\/+|\/+$/g, '')}` : folder,
        username: i.username,
        url: i.url, notes: i.notes, tags: i.tags,
        passkey: false, expires: null,
        hasPassword: Boolean(passwordToken), passwordToken,
        hasTotp: Boolean(totpToken), totpToken,
        totpConfig: i.totp ? { digits: i.totp.digits, period: i.totp.period, algorithm: i.totp.algorithm } : {},
        attachments: []
      });
      created++;
    } catch (err) {
      failed.push(`${i.name}: ${err.message ?? err}`);
    }
  }

  await vault.commit();
  await refreshFromVault();
  renderAll({ ohne: ['einstellungen'] });
  vault.fetchIcons?.().catch?.(() => {});

  if (failed.length) {
    console.warn('Import: nicht übernommen', failed);
    banner(`${created} importiert, ${failed.length} nicht übernommen (${esc(failed[0])}${failed.length > 1 ? ' …' : ''}).`, 'warning', 10000);
  } else {
    banner(`${created} Einträge aus ${result.source} importiert. Die Exportdatei jetzt am besten löschen.`, 'success', 8000);
  }
}

/**
 * Scheitert der Start, bleibt der Sperrbildschirm stehen und sagt, warum —
 * statt stumm eine leere Hauptseite zu zeigen, die nach offener Datenbank
 * aussieht.
 */
boot().catch(err => {
  console.error('Start fehlgeschlagen', err);
  $('#lockscreen').hidden = false;
  $('#lock-card').innerHTML = `
    ${BRAND_MARK}
    <h2>WKeePass konnte nicht starten</h2>
    <p class="lock-sub">${esc(err?.message ?? err)}</p>
    <div class="lock-actions">
      <button type="button" class="button hightlight" data-shape="full" id="boot-retry">
        <span class="msr">refresh</span>&nbsp;Neu laden</button>
    </div>`;
  $('#boot-retry').addEventListener('click', () => location.reload());
});
