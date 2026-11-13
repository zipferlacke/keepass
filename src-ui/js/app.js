import * as vault from './data/vault.js';
import * as settings from './data/settings.js';
import { applyAppearance } from './core/theme.js';
import { initI18n, t, uebersetzeSeite } from './core/i18n.js';
import * as pick from './ui/multiselect.js';
import { isTauri, isMobile, invoke, unlockMethods, listen } from './core/platform.js';
import { banner, selectPicker } from './ui/libs.js';
import { state, $, $$, esc } from './core/state.js';
import { bindTasten } from './pages/tasten.js';
import { seite, nachLaden, renderAll, refreshFromVault, syncFromFile, takeForeign } from './core/render.js';
import { renderTotp } from './pages/totp.js';
import { renderPasswords, renderSelectionBar, showContextMenu, closeContextMenu, autoRetitle } from './pages/entries.js';
import { renderSecurity } from './pages/checkup.js';
import { showView } from './core/navigation.js';
import { renderTags, renderHome } from './pages/home.js';
import { bindFileDrops } from './dialogs/entry.js';
import { markUsed } from './core/entries.js';
import { handleScan, startCreation } from './dialogs/create.js';
import { openKonflikte } from './dialogs/konflikte.js';
import { BRAND_MARK, dbName, enterUnlocked, gesperrtAufraeumen, lockDatabase, openUnlockDialog, rememberDatabase, renderLockscreen, showLockscreen, showOnlineQuestion, showWelcome, unlock, unlockBusy } from './pages/lock.js';
import { closeSettingsPage, renderSettings, showAndroidSetup, showBrowserSetupPage, updateSettingsPreview } from './pages/settings.js';

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
  await initI18n(settings.get('appearance.language', 'auto'));
  uebersetzeSeite();
  applyAppearance(settings.get('appearance', {}));

  // Datenbank, mit der die Anwendung aufgerufen wurde (z. B. Doppelklick auf
  // eine .kdbx-Datei); sie hat Vorrang vor der zuletzt benutzten.
  await adoptStartupDatabase();

  state.expanded = new Set(settings.get('ui.expandedFolders', []));
  state.unlock = await unlockMethods();

  // Der Kern sperrt nach Untätigkeit selbst. Hier werden wie beim Klick aufs
  // Schloss die Listen geleert und offene Dialoge geschlossen.
  await listen('vault-locked', async ev => {
    if (state.locked) return;
    document.querySelectorAll('dialog[open]').forEach(d => d.close());
    await gesperrtAufraeumen(String(ev?.payload ?? t('start.meldungen.untaetig')));
  });

  // Eingaben im Fenster melden dem Kern Aktivität (höchstens alle 30 s),
  // da Lesen und Scrollen sonst keinen Befehl auslösen.
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

  // Android: Autofill und Passkeys ändern die offene Datenbank ohne die
  // Oberfläche; die Liste wird danach neu geladen.
  await listen('vault-changed', async () => {
    if (state.locked) return;
    await refreshFromVault();
    renderAll({ ohne: ['einstellungen'] });
  });

  // Der Kern hat beim Speichern Änderungen eines anderen Geräts eingemischt.
  await listen('vault-merged', () => takeForeign());

  // Einträge, die hier und in der Datei verschieden geändert wurden:
  // der Konfliktdialog fragt, welche Fassung gilt.
  await listen('vault-conflicts', () => { if (!state.locked) openKonflikte(); });

  // Fremde Änderungen aus der Datei holen: höchstens alle fünf Minuten, wenn
  // das Fenster sichtbar ist (jeder Abgleich fragt bei Cloud-Speichern den
  // Server).
  const ABSTAND = 5 * 60_000;
  let zuletztAbgeglichen = Date.now();
  await listen('vault-unlocked', () => { zuletztAbgeglichen = Date.now(); });
  const syncNow = () => {
    if (state.locked || document.visibilityState !== 'visible') return;
    if (Date.now() - zuletztAbgeglichen < ABSTAND) return;
    zuletztAbgeglichen = Date.now();
    syncFromFile();
  };
  document.addEventListener('visibilitychange', syncNow);
  window.addEventListener('focus', syncNow);
  setInterval(syncNow, 60_000);

  await listen('autofill-saved', ev => {
    const n = Number(ev?.payload ?? 0);
    banner(t('start.meldungen.autofillGespeichert', { n }), 'success', 5000);
  });
  await listen('save-failed', ev => {
    banner(t('start.meldungen.nichtGespeichert', { grund: ev?.payload ?? '' }), 'error', 10000);
  });

  // .kdbx-Datei wird bei laufender App geöffnet (Single-Instance, macOS-
  // Systemereignis): Sperrbildschirm für genau diese Datei.
  await listen('open-database', async ev => {
    const path = String(ev?.payload ?? '');
    if (!path) return;
    await vault.startupDatabase().catch(() => null);   // gemerkten Startpfad verbrauchen
    if (!state.locked && path === settings.get('database.current', null)) return;
    if (!state.locked) await lockDatabase();
    await settings.set('database.current', path, { silent: true });
    await rememberDatabase({ name: dbName(path), path });
    state.unlock = await unlockMethods(path);
    renderLockscreen();
  });

  await bindOtpLinks();

  // Auswahlfelder im Stil der Oberfläche.
  selectPicker();

  await bindBrowserRequests();
  await bindFileDrops();
  bindStaticEvents();

  // Bei geänderter Auswahl wird die Liste neu gezeichnet (Kästchen ein-/ausblenden).
  pick.onSelectionChange(() => {
    renderAll({ ohne: ['einstellungen'] });
    renderSelectionBar();
  });

  // Steuerfläche für tauri-agent-tools (siehe tools/screenshots.sh): nur
  // Ansichtswechsel und Lesezugriffe, keine Geheimnisse.
  window.showView = showView;
  window.wkeepass = {
    showView,
    view: () => state.view,
    ready: () => !state.locked,
    entryCount: () => state.entries.length
  };

  await showLockscreen();

  // Am Rechner kann das Hauptfenster erst nach dem Entsperren im kleinen
  // Browser-Fenster entstehen; eine im Kern offene Datenbank wird dann
  // übernommen, sonst folgt der Sperrbildschirm.
  if (isTauri && !isMobile && await vault.adopt().then(() => true, () => false)) {
    await enterUnlocked();
    return;
  }

  // Einrichtung beim ersten Start.
  if (!settings.get('ui.welcomeSeen', false)) await showWelcome();
  if (!settings.get('ui.onlineAsked', false)) await showOnlineQuestion();
  if (isMobile && !settings.get('android.setupSeen', false)) await showAndroidSetup();
  if (isTauri && !isMobile && !settings.get('browser.setupSeen', false)) await showBrowserSetupPage();
  renderLockscreen();

  // Ist die Datenbank an das Gerät gebunden (z. B. Windows Hello), wird beim
  // Programmstart sofort entsperrt. Entfällt nach manuellem Sperren und wenn
  // Browser oder Handy-Ausfüllen die App gestartet haben; diese fragen selbst.
  const fuerAndere = isTauri && await invoke('started_for_others').catch(() => false);
  if (!fuerAndere && state.unlock.device && settings.get('database.current', null)) unlock({ method: 'device' });
}

/**
 * Nimmt otpauth://-Codes aus anderen Apps entgegen (Android: „Öffnen mit
 * WKeePass"), per Deep-Link-Plugin beim Kaltstart oder als Ereignis. Bei
 * gesperrter Datenbank wird der Code bis zum Entsperren vorgehalten.
 */
async function bindOtpLinks() {
  if (!isTauri) return;
  const take = urls => {
    const uri = [urls].flat().map(String).find(u => /^otpauth(-migration)?:/i.test(u));
    if (!uri) return;
    if (state.locked) {
      state.pendingOtp = uri;
      banner(t('start.meldungen.codeNachEntsperren'), 'info', 6000);
    } else {
      handleScan(uri);
    }
  };
  try { take(await invoke('plugin:deep-link|get_current') ?? []); } catch { /* Plugin fehlt */ }
  try { await listen('deep-link://new-url', ev => take(ev?.payload ?? [])); } catch { /* dito */ }
}

/**
 * Wählt die Datenbank aus, mit der die Anwendung aufgerufen wurde, und trägt
 * sie unter „zuletzt genutzt" ein. Geöffnet wird sie nicht; das
 * Master-Passwort wird weiterhin abgefragt.
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
   Die Rückfrage und das Entsperren zeigt ein eigenes kleines Fenster
   (`request.html`), das der Kern über dem Browser öffnet. Hier wird nur
   das Hauptfenster nachgeführt, falls es daneben offen ist.
   ========================================================= */

async function bindBrowserRequests() {
  // Die Browser-Erweiterung gibt es nur am Rechner.
  if (isMobile) return;

  await listen('browser-needs-unlock', () => {
    if (!state.locked) return;
    banner(t('start.browser.wartet'), 'info', 8000);
  });

  // Entsperren im kleinen Fenster: das Hauptfenster wechselt vom
  // Sperrbildschirm zur geöffneten Datenbank. Hat dieses Fenster selbst
  // entsperrt, ist `state.locked` bereits false.
  await listen('vault-unlocked', async () => {
    if (!state.locked || unlockBusy()) return;

    // `vault.js` muss die im Kern offene Datenbank übernehmen, bevor die Liste entsteht.
    await vault.adopt();

    await enterUnlocked();
    banner(t('start.browser.entsperrt'), 'success', 4000);
  });

  // Die Erweiterung legt Einträge und Passkeys an oder ändert sie; die Liste
  // wird neu geladen.
  await listen('browser-saved', async () => {
    if (state.locked) return;
    await refreshFromVault();
    renderAll({ ohne: ['einstellungen'] });
  });

  // Die Datei am Speicherort war nicht erreichbar; der Kern schreibt beim
  // nächsten Abgleich nach.
  await listen('vault-sync-failed', ev => {
    banner(t('start.meldungen.dateiNachgeholt', { grund: ev?.payload ?? '' }), 'warning', 8000);
  });

  await listen('browser-save-failed', ev => {
    banner(t('start.browser.nichtGespeichert', { grund: ev?.payload ?? '' }), 'error', 10000);
  });
}


function bindStaticEvents() {
  $('#search').addEventListener('input', e => {
    state.search = e.target.value.trim().toLowerCase();
    renderPasswords();
  });

  $$('.app-nav button[data-view]').forEach(btn =>
    btn.addEventListener('click', () => {
      // Der Typfilter gilt nur für Aufrufe über die Kacheln.
      state.kindFilter = null;
      showView(btn.dataset.view);
    }));

  $('#btn-lock').addEventListener('click', lockDatabase);
  $('#btn-close-settings').addEventListener('click', closeSettingsPage);

  // Kontextmenü für die ganze Passwortansicht
  $('#view-passwords').addEventListener('contextmenu', ev => {
    if (ev.target.closest('input, textarea, select')) return;
    if (ev.target.closest('tr[data-id], tr.tv-group-row[data-folder]')) return;   // diese haben eigene Menüs
    ev.preventDefault();
    showContextMenu(ev.clientX, ev.clientY, {});
  });

  document.addEventListener('click', ev => {
    if (!ev.target.closest('.context-menu, [data-menu]')) closeContextMenu();
  });
  document.addEventListener('keydown', ev => { if (ev.key === 'Escape') closeContextMenu(); });
  window.addEventListener('scroll', closeContextMenu, true);
  $('#btn-add').addEventListener('click', startCreation);
  bindTasten();

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


/** Liefert den übersetzten Text oder `ersatz`, wenn die Sprache noch nicht geladen ist. */
function tSicher(schluessel, ersatz) {
  const text = t(schluessel);
  return text === schluessel ? ersatz : text;
}

// Scheitert der Start, zeigt der Sperrbildschirm den Fehler.
boot().catch(err => {
  console.error('Start fehlgeschlagen', err);
  $('#lockscreen').hidden = false;
  $('#lock-card').innerHTML = `
    ${BRAND_MARK}
    <h2>${tSicher('start.fehler.titel', 'WKeePass konnte nicht starten')}</h2>
    <p class="lock-sub">${esc(err?.message ?? err)}</p>
    <div class="lock-actions">
      <button type="button" class="button hightlight" data-shape="full" id="boot-retry">
        <span class="msr">refresh</span>&nbsp;${tSicher('start.fehler.neuLaden', 'Neu laden')}</button>
    </div>`;
  $('#boot-retry').addEventListener('click', () => location.reload());
});
