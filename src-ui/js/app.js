import * as vault from './data/vault.js';
import * as settings from './data/settings.js';
import { applyAppearance } from './core/theme.js';
import * as pick from './ui/multiselect.js';
import { isTauri, isMobile, invoke, unlockMethods, listen } from './core/platform.js';
import { banner, selectPicker } from './ui/libs.js';
import { state, $, $$, esc } from './core/state.js';
import { seite, nachLaden, renderAll, refreshFromVault, syncFromFile, takeForeign } from './core/render.js';
import { renderTotp } from './pages/totp.js';
import { renderPasswords, renderSelectionBar, showContextMenu, closeContextMenu, autoRetitle } from './pages/entries.js';
import { renderSecurity } from './pages/checkup.js';
import { showView } from './core/navigation.js';
import { renderTags, renderHome } from './pages/home.js';
import { bindFileDrops } from './dialogs/entry.js';
import { markUsed } from './core/entries.js';
import { handleScan, startCreation } from './dialogs/create.js';
import { BRAND_MARK, dbName, enterUnlocked, lockDatabase, openUnlockDialog, rememberDatabase, renderLockscreen, showLockscreen, showWelcome, unlock, unlockBusy } from './pages/lock.js';
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
