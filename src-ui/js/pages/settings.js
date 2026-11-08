/**
 * settings.js — die Seite mit den Einstellungen.
 *
 * Ein Markup für beide Orte (Einstellungsseite und Zahnrad auf dem
 * Sperrbildschirm), dazu die Abschnitte, die eigene Logik haben: Android
 * (Autofill, Passkeys, Kamera), die Datenbank (Name, Verschlüsselungsstärke,
 * Versionen) und die Browser-Anbindung.
 */

import * as vault from '../data/vault.js';
import * as settings from '../data/settings.js';
import { applyAppearance, applyTheme, applyPrimary } from '../core/theme.js';
import { hostFromUrl } from '../core/icons.js';
import * as preview from '../data/preview.js';
import { isTauri, isMobile, invoke } from '../core/platform.js';
import { dialog, banner } from '../ui/libs.js';
import { t, gebiet, sprachListe } from '../core/i18n.js';
import { state, $, esc } from '../core/state.js';
import { autoRetitle, adoptTitles, emptyBin } from './entries.js';
import { showView } from '../core/navigation.js';
import { importFromOtherApps } from '../dialogs/create.js';
import { openVersionsDialog } from '../dialogs/versions.js';
import { BRAND_MARK, deviceName, changePin, clearAppPin, createAppPin, manageAccess, pfadLabel, recentDatabases, renderLockscreen, resetToHomeView, unlock } from './lock.js';

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
  const sprache = s.appearance?.language ?? 'auto';
  const dbSettings = settings.forDatabase(s.database?.current ?? null);

  return `
    <div class="settings-group">
      <div class="section-label">${t('einstellungen.darstellung.titel')}</div>
      <div class="settings-card">
        <div class="setting">
          <div class="setting-label"><strong>${t('einstellungen.darstellung.farbschema')}</strong><small>${t('einstellungen.darstellung.farbschemaHinweis')}</small></div>
          <div class="setting-control">
            <div class="group-radio" id="theme-switch">
              ${[['light', t('einstellungen.darstellung.hell')], ['dark', t('einstellungen.darstellung.dunkel')], ['system', t('einstellungen.darstellung.system')]].map(([value, label]) => `
                <label>
                  <input type="radio" name="appearance.theme" value="${value}" ${theme === value ? 'checked' : ''}>${label}
                </label>`).join('')}
            </div>
          </div>
        </div>
        <div class="setting">
          <div class="setting-label"><strong>${t('einstellungen.darstellung.akzentfarbe')}</strong><small>${t('einstellungen.darstellung.akzentfarbeHinweis')}</small></div>
          <div class="setting-control">
            <input type="color" id="primary-color" name="appearance.primary" value="${esc(s.appearance?.primary ?? '#2FA69A')}">
          </div>
        </div>
        <div class="setting">
          <div class="setting-label"><strong>${t('einstellungen.darstellung.sprache')}</strong><small>${t('einstellungen.darstellung.spracheHinweis')}</small></div>
          <div class="setting-control">
            <select id="app-language" name="appearance.language" data-sp-picker data-sp-search="false" aria-label="${t('einstellungen.darstellung.sprache')}">
              <option value="auto" ${sprache === 'auto' ? 'selected' : ''}>${t('einstellungen.darstellung.spracheAuto')}</option>
              ${sprachListe().map(l => `<option value="${esc(l.code)}" ${sprache === l.code ? 'selected' : ''}>${esc(l.name)}</option>`).join('')}
            </select>
          </div>
        </div>
      </div>
    </div>

    ${state.locked ? '' : `<div class="settings-group" data-needs-db>
      <div class="section-label">${t('einstellungen.datenbank.titel')}</div>
      <div class="settings-card">
        <div id="database-card">
          <div class="setting"><div class="setting-label"><small>${t('einstellungen.allgemein.wirdGeladen')}</small></div></div>
        </div>
        <div class="setting">
          <div class="setting-label">
            <strong>${t('einstellungen.datenbank.entsperren')}</strong>
            <small>${[state.unlock.device ? esc(deviceName()) : null, state.unlock.pin ? t('einstellungen.datenbank.pin') : null, state.unlock.biometric ? t('einstellungen.datenbank.fingerabdruck') : null]
              .filter(Boolean).join(t('einstellungen.datenbank.und')) || t('einstellungen.datenbank.nurMaster')}</small>
            <small>${t('einstellungen.datenbank.appMethoden', { link: `<button type="button" class="link-btn" data-scroll="app-unlock">${t('einstellungen.datenbank.appMethodenLink')}</button>` })}</small>
          </div>
          <div class="setting-control"><button type="button" class="button" id="btn-access">${t('einstellungen.datenbank.waehlen')}</button></div>
        </div>
        <div class="setting">
          <div class="setting-label"><strong>${t('einstellungen.datenbank.warnen')}</strong><small>${t('einstellungen.datenbank.warnenHinweis')}</small></div>
          <div class="setting-control">
            <input type="number" inputmode="numeric" min="1" max="180" data-set-db="expiryWarnDays" name="db.expiryWarnDays" value="${dbSettings.expiryWarnDays ?? 14}">
          </div>
        </div>
        <div class="setting">
          <div class="setting-label"><strong>${t('einstellungen.datenbank.papierkorb')}</strong><small>${t('einstellungen.datenbank.papierkorbHinweis')}</small></div>
          <div class="setting-control"><button type="button" class="button" id="btn-empty-bin">${t('einstellungen.datenbank.papierkorbKnopf')}</button></div>
        </div>
      </div>
    </div>`}

    <div class="settings-group">
      <div class="section-label">${t('einstellungen.sperren.titel')}</div>
      <div class="settings-card">
        <div class="setting">
          <div class="setting-label"><strong>${t('einstellungen.sperren.automatisch')}</strong><small>${t('einstellungen.sperren.automatischHinweis')}</small></div>
          <div class="setting-control"><input type="number" inputmode="numeric" min="1" max="120" data-set="unlock.autoLockMinutes" name="unlock.autoLockMinutes" value="${s.unlock?.autoLockMinutes ?? 5}"></div>
        </div>
        <div class="setting">
          <div class="setting-label"><strong>${t('einstellungen.sperren.zwischenablage')}</strong><small>${t('einstellungen.sperren.zwischenablageHinweis')}</small></div>
          <div class="setting-control"><input type="number" inputmode="numeric" min="0" max="300" data-set="unlock.clipboardClearSeconds" name="unlock.clipboardClearSeconds" value="${s.unlock?.clipboardClearSeconds ?? 30}"></div>
        </div>
      </div>
    </div>

    ${isMobile ? `<div class="settings-group">
      <div class="section-label">Android</div>
      <div class="settings-card" id="android-card">
        <div class="setting"><div class="setting-label"><small>${t('einstellungen.allgemein.wirdGeladen')}</small></div></div>
      </div>
    </div>` : ''}

    ${isMobile ? '' : `<div class="settings-group">
      <div class="section-label">${t('einstellungen.browser.titel')}</div>
      <div class="settings-card" id="browser-card">
        <div class="setting"><div class="setting-label"><small>${t('einstellungen.allgemein.wirdGeladen')}</small></div></div>
      </div>
    </div>`}

    <div class="settings-group">
      <div class="section-label">${t('einstellungen.eintraege.titel')}</div>
      <div class="settings-card">
        <div class="setting" data-needs-db>
          <div class="setting-label"><strong>${t('einstellungen.eintraege.importieren')}</strong>
            <small>${t('einstellungen.eintraege.importierenHinweis')}</small></div>
          <div class="setting-control"><button type="button" class="button" id="btn-import-entries">${t('einstellungen.eintraege.importierenKnopf')}</button></div>
        </div>
        <div class="setting">
          <div class="setting-label">
            <strong>${t('einstellungen.eintraege.iconsLaden')}</strong>
            <small>${t('einstellungen.eintraege.iconsLadenHinweis')}</small>
          </div>
          <div class="setting-control"><input type="checkbox" data-shape="toggle" data-set="icons.download" name="icons.download" ${s.icons?.download ? 'checked' : ''}></div>
        </div>
        <div class="setting" data-needs-db>
          <div class="setting-label"><strong>${t('einstellungen.eintraege.iconsNeu')}</strong><small>${t('einstellungen.eintraege.iconsNeuHinweis')}</small></div>
          <div class="setting-control"><button type="button" class="button" id="btn-refresh-icons"><span class="msr">refresh</span>&nbsp;${t('einstellungen.eintraege.iconsNeuKnopf')}</button></div>
        </div>
        <div class="setting">
          <div class="setting-label"><strong>${t('einstellungen.eintraege.namen')}</strong>
            <small>${t('einstellungen.eintraege.namenHinweis')}</small>
            <small data-needs-db>${t('einstellungen.eintraege.namenPruefenHinweis')}</small></div>
          <div class="setting-control control-pair">
            <input type="checkbox" data-shape="toggle" data-set="names.fromWebsite" name="names.fromWebsite" ${s.names?.fromWebsite ?? true ? 'checked' : ''} aria-label="${t('einstellungen.eintraege.namenAutomatisch')}">
            <button type="button" class="button" id="btn-adopt-titles" data-needs-db><span class="msr">travel_explore</span>&nbsp;${t('einstellungen.eintraege.namenPruefen')}</button>
          </div>
        </div>
      </div>
    </div>

    <div class="settings-group">
      <div class="section-label">${t('einstellungen.pruefungen.titel')}</div>
      <div class="settings-card">
        <div class="setting">
          <div class="setting-label"><strong>${t('einstellungen.pruefungen.staerke')}</strong><small>${t('einstellungen.pruefungen.staerkeHinweis')}</small></div>
          <div class="setting-control"><input type="checkbox" data-shape="toggle" data-set="checks.passwordStrength" name="checks.passwordStrength" ${s.checks?.passwordStrength ? 'checked' : ''}></div>
        </div>
        <div class="setting">
          <div class="setting-label"><strong>${t('einstellungen.pruefungen.mehrfach')}</strong><small>${t('einstellungen.pruefungen.mehrfachHinweis')}</small></div>
          <div class="setting-control"><input type="checkbox" data-shape="toggle" data-set="checks.reuseDetection" name="checks.reuseDetection" ${s.checks?.reuseDetection ? 'checked' : ''}></div>
        </div>
        <div class="setting">
          <div class="setting-label"><strong>${t('einstellungen.pruefungen.vorwarn')}</strong><small>${t('einstellungen.pruefungen.vorwarnHinweis')}</small></div>
          <div class="setting-control"><input type="number" inputmode="numeric" min="1" max="180" data-set="checks.expiryWarnDays" name="checks.expiryWarnDays" value="${s.checks?.expiryWarnDays ?? 14}"></div>
        </div>
        <div class="setting">
          <div class="setting-label"><strong>${t('einstellungen.pruefungen.leaks')}</strong><small>${t('einstellungen.pruefungen.leaksHinweis')}</small></div>
          <div class="setting-control"><input type="checkbox" data-shape="toggle" data-set="checks.passwordBreach" name="checks.passwordBreach" ${s.checks?.passwordBreach ? 'checked' : ''}></div>
        </div>
        <div class="setting">
          <div class="setting-label"><strong>${t('einstellungen.pruefungen.email')}</strong><small>${t('einstellungen.pruefungen.emailHinweis')}</small></div>
          <div class="setting-control"><input type="checkbox" data-shape="toggle" data-set="checks.emailBreach" name="checks.emailBreach" ${s.checks?.emailBreach ? 'checked' : ''}></div>
        </div>
        <div class="setting">
          <div class="setting-label"><strong>${t('einstellungen.pruefungen.benachrichtigen')}</strong><small>${t('einstellungen.pruefungen.benachrichtigenHinweis')}</small></div>
          <div class="setting-control"><input type="checkbox" data-shape="toggle" data-set="checks.notify" name="checks.notify" ${s.checks?.notify !== false ? 'checked' : ''}></div>
        </div>
        <div class="setting">
          <div class="setting-label">
            <strong>${t('einstellungen.pruefungen.automatisch')}</strong>
            <small>${t('einstellungen.pruefungen.automatischHinweis')}${s.checks?.lastRunAt ? t('einstellungen.pruefungen.zuletzt', { datum: new Date(s.checks.lastRunAt).toLocaleDateString(gebiet()) }) : ''}</small>
          </div>
          <div class="setting-control">
            <div class="group-radio" id="auto-check">
              ${[['daily', t('einstellungen.pruefungen.taeglich')], ['weekly', t('einstellungen.pruefungen.woechentlich')], ['off', t('einstellungen.pruefungen.aus')]].map(([value, label]) => `
                <label>
                  <input type="radio" name="checks.automatic" value="${value}"
                    ${(s.checks?.automatic ?? 'off') === value ? 'checked' : ''}>${label}
                </label>`).join('')}
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="settings-group" id="app-unlock">
      <div class="section-label">${t('einstellungen.datenbank.appMethodenLink')}</div>
      <div class="settings-card">
        <p class="setting-intro">${t('einstellungen.appEntsperren.einleitung')}</p>
        <div class="setting">
          <div class="setting-label">
            <strong>${t('einstellungen.appEntsperren.biometrie')}</strong>
            <small>${state.unlock.deviceAvailable
              ? t('einstellungen.appEntsperren.biometrieGeraet', { geraet: esc(deviceName()) })
              : state.unlock.biometricAvailable
                ? t('einstellungen.appEntsperren.biometrieFinger')
                : t('einstellungen.appEntsperren.biometrieNicht')}</small>
          </div>
          <div class="setting-control"><input type="checkbox" data-shape="toggle" data-set="unlock.biometrics" name="unlock.biometrics" ${s.unlock?.biometrics ? 'checked' : ''} ${state.unlock.biometricAvailable || state.unlock.deviceAvailable ? '' : 'disabled'}></div>
        </div>
        <div class="setting">
          <div class="setting-label">
            <strong>${t('einstellungen.appEntsperren.pin')}</strong>
            <small>${state.unlock.pinSet
              ? (state.unlock.keyring
                  ? t('einstellungen.appEntsperren.pinSchluesselbund')
                  : t('einstellungen.appEntsperren.pinOhne'))
              : t('einstellungen.appEntsperren.pinKeine')}</small>
          </div>
          <div class="setting-control">
            ${state.unlock.pinSet
              ? `<button type="button" class="button" id="btn-pin-change">${t('einstellungen.appEntsperren.aendern')}</button>
                 <button type="button" class="button" id="btn-pin-clear">${t('einstellungen.appEntsperren.entfernen')}</button>`
              : `<button type="button" class="button" id="btn-pin-create">${t('einstellungen.appEntsperren.festlegen')}</button>`}
          </div>
        </div>
      </div>
    </div>

    <div class="settings-group">
      <div class="section-label">${t('einstellungen.export.titel')}</div>
      <div class="settings-card">
        <div class="setting">
          <div class="setting-label"><strong>${t('einstellungen.export.exportieren')}</strong><small>${t('einstellungen.export.exportierenHinweis')}</small></div>
          <div class="setting-control"><button type="button" class="button" id="btn-export">${t('einstellungen.export.exportierenKnopf')}</button></div>
        </div>
        <div class="setting">
          <div class="setting-label"><strong>${t('einstellungen.export.importieren')}</strong><small>${t('einstellungen.export.importierenHinweis')}</small></div>
          <div class="setting-control"><button type="button" class="button" id="btn-import">${t('einstellungen.export.importierenKnopf')}</button></div>
        </div>
        <div class="setting">
          <div class="setting-label"><strong>${t('einstellungen.export.zuruecksetzen')}</strong><small>${t('einstellungen.export.zuruecksetzenHinweis')}</small></div>
          <div class="setting-control"><button type="button" class="button" id="btn-reset">${t('einstellungen.export.zuruecksetzenKnopf')}</button></div>
        </div>
      </div>
    </div>

    <details class="settings-group settings-raw">
      <summary class="section-label">${t('einstellungen.export.konfiguration')}</summary>
      <div class="settings-card">
        <pre id="settings-preview">${esc(settings.exportSettings())}</pre>
      </div>
    </details>

    <p class="app-version" id="app-version">WKeePass</p>`
}

/**
 * Scrollt zu einem Abschnitt der Einstellungen, sodass er unter der
 * Kopfzeile steht. `scrollIntoView` schöbe ihn unter die Kopfzeile.
 */
function springeZu(id) {
  const ziel = document.getElementById(id);
  if (!ziel) return;
  let box = ziel.parentElement;
  while (box && !/(auto|scroll)/.test(getComputedStyle(box).overflowY)) box = box.parentElement;
  // Ohne eigenen Scrollbereich scrollt das Dokument.
  box ??= document.scrollingElement;
  const oben = box === document.scrollingElement ? 0 : box.getBoundingClientRect().top;
  const kopf = document.querySelector('.app-header, header')?.getBoundingClientRect().bottom ?? 0;
  box.scrollBy({ top: ziel.getBoundingClientRect().top - Math.max(oben, kopf) - 8, behavior: 'smooth' });
}

export function renderSettings() {
  const body = $('#settings-body');
  body.innerHTML = settingsMarkup();
  wireSettings(body);

  // Nachgereicht: Der Zustand kommt aus dem Kern und würde das Zeichnen
  // sonst aufhalten.
  renderBrowserSection();
  renderDatabaseSection();
  renderAndroidSection($('#android-card'));
  zeigeVersion();
}

/** Die Versionsnummer ganz unten — dieselbe wie in tauri.conf.json. */
async function zeigeVersion() {
  const el = $('#app-version');
  if (!el) return;
  try {
    el.textContent = `WKeePass ${await invoke('plugin:app|version')}`;
  } catch {
    // Im Browser ohne Tauri gibt es keine App-Version.
    el.textContent = t('einstellungen.allgemein.demo');
  }
}

/* =========================================================
   Android: Passwortmanager, Passkeys, Kamera
   ---------------------------------------------------------
   Drei Freigaben, die nur der Nutzer erteilen kann — jeweils in einer
   anderen Ecke der Systemeinstellungen. Hier steht, was davon steht, und
   ein Knopf führt genau dorthin, wo es fehlt.
   ========================================================= */

const androidFreigaben = () => [
  { key: 'autofill', icon: 'password', title: t('einstellungen.android.passwortmanager'),
    text: t('einstellungen.android.passwortmanagerText'),
    action: t('einstellungen.android.passwortmanagerAktion') },
  { key: 'passkeys', icon: 'passkey', title: t('einstellungen.android.passkeys'),
    text: t('einstellungen.android.passkeysText'),
    action: t('einstellungen.android.passkeysAktion'), missing: t('einstellungen.android.passkeysFehlt') },
  { key: 'kamera', icon: 'photo_camera', title: t('einstellungen.android.kamera'),
    text: t('einstellungen.android.kameraText'),
    action: t('einstellungen.android.kameraAktion') }
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
        <strong>${t('einstellungen.stufe.titel')}</strong>
        <small>${t('einstellungen.android.stufeHinweis')}</small>
      </div>
      <div class="setting-control">
        <div class="group-radio" id="android-guard">
          ${[['never', t('einstellungen.stufe.nichts')], ['confirm', t('einstellungen.stufe.bestaetigen')], ['identify', t('einstellungen.stufe.legitimieren')]]
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
        <strong>${t('einstellungen.frist.titel')}</strong>
        <small>${t('einstellungen.android.fristHinweis')}</small>
      </div>
      <div class="setting-control">
        <select id="android-grace" name="android.graceSeconds" data-sp-picker data-sp-search="false">
          ${[[0, t('einstellungen.frist.jedesMal')], [30, t('einstellungen.frist.sek30')], [60, t('einstellungen.frist.min1')], [300, t('einstellungen.frist.min5')], [900, t('einstellungen.frist.min15')]]
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

  card.insertAdjacentHTML('beforeend', androidFreigaben().map(f => {
    const s = status[f.key] ?? {};
    const control = s.aktiv
      ? `<span class="setting-state" data-tone="ok"><span class="msr">check_circle</span>${t('einstellungen.android.aktiv')}</span>`
      : !s.moeglich
        ? `<span class="setting-state">${esc(f.missing ?? t('einstellungen.android.nichtVerfuegbar'))}</span>`
        : `<button type="button" class="button hightlight" data-setup="${f.key}">
            ${s.gesperrt ? t('einstellungen.android.inAppErlauben') : esc(f.action)}</button>`;
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
        never: t('einstellungen.android.stufeNichts'),
        confirm: t('einstellungen.stufe.bestaetigenMeldung'),
        identify: t('einstellungen.android.stufeLegitimieren')
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
export async function showAndroidSetup() {
  return new Promise(resolve => {
    $('#welcome').hidden = false;
    $('#welcome-card').innerHTML = `
      ${BRAND_MARK}
      <h2>${t('einstellungen.androidStart.titel')}</h2>
      <p class="lock-sub">${t('einstellungen.androidStart.text')}</p>
      <div class="settings-card" id="android-setup"></div>
      <div class="lock-actions">
        <button type="button" class="button hightlight" data-shape="full" id="as-done"><span class="msr">check</span>&nbsp;${t('einstellungen.allgemein.weiter')}</button>
        <button type="button" class="button" data-shape="full" id="as-later">${t('einstellungen.allgemein.spaeter')}</button>
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

/** Wie im Kern (database.rs): Wert, Name, Hinweis, Durchgänge, MiB, Fäden. */
/**
 * Eine Stufe als Feld [Wert, Name, Hinweis, Durchgänge, MiB, Fäden]. Name und
 * Hinweis werden erst beim Lesen übersetzt — beim Import ist i18n noch nicht
 * geladen, und lock.js zerlegt das Feld weiterhin per Destrukturierung.
 */
function stufe(wert, nameKey, hinweisKey, it, mib, p) {
  const f = [wert, null, null, it, mib, p];
  Object.defineProperty(f, 1, { get: () => t(nameKey), enumerable: true });
  Object.defineProperty(f, 2, { get: () => t(hinweisKey), enumerable: true });
  return f;
}

export const STUFEN = [
  stufe('schnell', 'einstellungen.verschluesselung.stufeSchnell', 'einstellungen.verschluesselung.hinweisSchnell', 10, 16, 2),
  stufe('zuegig', 'einstellungen.verschluesselung.stufeZuegig', 'einstellungen.verschluesselung.hinweisZuegig', 20, 16, 2),
  stufe('standard', 'einstellungen.verschluesselung.stufeStandard', 'einstellungen.verschluesselung.hinweisStandard', 40, 16, 4),
  stufe('erhoeht', 'einstellungen.verschluesselung.stufeErhoeht', 'einstellungen.verschluesselung.hinweisErhoeht', 10, 64, 4),
  stufe('hoch', 'einstellungen.verschluesselung.stufeHoch', 'einstellungen.verschluesselung.hinweisHoch', 14, 128, 4),
  stufe('stark', 'einstellungen.verschluesselung.stufeStark', 'einstellungen.verschluesselung.hinweisStark', 20, 256, 4)
];

/** Auf der Skala beschriftet sind nur diese — die beiden dazwischen nicht. */
const BENANNT = new Set(['schnell', 'standard', 'stark']);

/** „10 Durchgänge · 64 MiB · 4 Fäden" */
const kdfWerte = (it, mib, p) => t('einstellungen.verschluesselung.werte', { it, mib, faeden: t('einstellungen.verschluesselung.faeden', { n: p }) });

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

/** Was hinter Durchgängen, Speicher und Fäden steckt — hinter dem ⓘ. */
function kdfErklaeren() {
  dialog({
    title: t('einstellungen.verschluesselung.titel'),
    content: `
      <p>${t('einstellungen.verschluesselung.erklaerung.einleitung')}</p>
      <dl class="kdf-begriffe">
        <dt>${t('einstellungen.verschluesselung.erklaerung.durchgaengeBegriff')}</dt>
        <dd>${t('einstellungen.verschluesselung.erklaerung.durchgaenge')}</dd>
        <dt>${t('einstellungen.verschluesselung.erklaerung.speicherBegriff')}</dt>
        <dd>${t('einstellungen.verschluesselung.erklaerung.speicher')}</dd>
        <dt>${t('einstellungen.verschluesselung.erklaerung.faedenBegriff')}</dt>
        <dd>${t('einstellungen.verschluesselung.erklaerung.faeden')}</dd>
        <dt>${t('einstellungen.verschluesselung.erklaerung.eigenBegriff')}</dt>
        <dd>${t('einstellungen.verschluesselung.erklaerung.eigen')}</dd>
      </dl>`,
    confirmText: null,
    cancelText: t('allgemein.knoepfe.schliessen'),
    barRight: { icon: '<span class="msr">close</span>', title: t('allgemein.knoepfe.schliessen'), action: 'cancel' }
  });
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
      <strong>${t('einstellungen.allgemein.nichtVerfuegbar')}</strong><small>${esc(err.message)}</small></div></div>`;
    return;
  }

  const path = settings.get('database.current', null);
  const eintrag = recentDatabases().find(d => d.path === path);
  let eigen = info.level === 'eigen';
  let stufe = eigen
    ? naechsteStufe(info.iterations, info.memoryMib)
    : Math.max(0, STUFEN.findIndex(([wert]) => wert === info.level));
  const hinweis = i => eigen && i === stufe && Number(regler?.value ?? stufe) === stufe
    ? t('einstellungen.verschluesselung.eigenHinweis', { stufe: STUFEN[i][1] })
    : STUFEN[i][2];
  let regler = null;

  card.innerHTML = `
    <div class="setting db-name-row">
      <div class="setting-label">
        <strong>${t('einstellungen.datenbank.name')}</strong>
        <small>${path ? esc(pfadLabel(path, eintrag?.label)) : t('einstellungen.datenbank.nameInDatei')}<span id="db-modified"></span></small>
      </div>
      <div class="setting-control">
        <input type="text" id="db-name" value="${esc(info.name)}" placeholder="${t('einstellungen.datenbank.namePlatzhalter')}"
               aria-label="${t('einstellungen.datenbank.name')}" ${info.readOnly ? 'disabled' : ''}>
      </div>
    </div>

    <div class="setting" data-stacked>
      <div class="setting-label">
        <strong>Verschlüsselungsstärke
          <button type="button" class="info-btn" id="kdf-info" title="${t('einstellungen.verschluesselung.werteFrage')}"
                  aria-label="${t('einstellungen.verschluesselung.werteFrage')}"><span class="msr">info</span></button></strong>
        <small>${t('einstellungen.verschluesselung.hinweis')}</small>
      </div>
      <div class="setting-control kdf-slider">
        <input type="range" id="db-level" min="0" max="${STUFEN.length - 1}" step="1" value="${stufe}"
               aria-label="${t('einstellungen.verschluesselung.titel')}" ${info.readOnly ? 'disabled' : ''}>
        <div class="kdf-labels">
          ${STUFEN.map(([wert, name], i) => `<button type="button" data-stufe="${i}" ${i === stufe ? 'aria-current="true"' : ''}
            ${BENANNT.has(wert) ? '' : 'data-zwischen'} title="${esc(name)}"
            ${info.readOnly ? 'disabled' : ''}>${BENANNT.has(wert) ? name : '·'}</button>`).join('')}
        </div>
        <small class="kdf-note" id="db-level-note"></small>
        <small class="kdf-values" id="db-level-values"></small>
        <small class="kdf-values" id="db-details">${esc(info.format)} · ${esc(info.cipher)} · ${esc(info.kdf)}</small>
        <div class="kdf-apply" id="db-level-apply" hidden>
          <button type="button" class="button" id="db-level-undo">${t('allgemein.knoepfe.zurueck')}</button>
          <button type="button" class="button hightlight" id="db-level-ok">${t('einstellungen.allgemein.uebernehmen')}</button>
        </div>
      </div>
    </div>

    <div class="setting">
      <div class="setting-label">
        <strong>${t('einstellungen.versionen.titel')}</strong>
        <small>${t('einstellungen.versionen.hinweis')}</small>
      </div>
      <div class="setting-control">
        <button type="button" class="button" id="btn-versions">${t('einstellungen.versionen.ansehen')}</button>
      </div>
    </div>

    <div class="setting">
      <div class="setting-label">
        <strong>${t('einstellungen.versionen.aufheben')}</strong>
        <small>${t('einstellungen.versionen.aufhebenBereich')}</small>
      </div>
      <div class="setting-control">
        <input type="number" inputmode="numeric" min="30" max="100" id="versions-keep" name="versions.keep"
          aria-label="${t('einstellungen.versionen.aufhebenFrage')}" value="${Math.min(100, Math.max(30, Number(settings.get('versions.keep', 30)) || 30))}">
      </div>
    </div>
`;

  card.querySelector('#btn-versions')?.addEventListener('click', () => openVersionsDialog());
  card.querySelector('#versions-keep')?.addEventListener('change', async ev => {
    const anzahl = Math.min(100, Math.max(30, Math.round(Number(ev.target.value)) || 30));
    ev.target.value = anzahl;
    await settings.set('versions.keep', anzahl, { silent: true });
    banner(t('einstellungen.versionen.aufgehoben', { n: anzahl }), 'success', 1600);
  });
  card.querySelector('#kdf-info')?.addEventListener('click', kdfErklaeren);

  const speichern = async (feld, wert) => {
    try {
      await vault.setSecurity(wert);
      banner(feld === 'name' ? t('einstellungen.datenbank.nameGespeichert') : t('einstellungen.verschluesselung.geaendert'), 'success');
      renderDatabaseSection();
    } catch (err) {
      banner(t('einstellungen.allgemein.nichtGespeichert', { fehler: err.message }), 'error', 6000);
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
  const werte = card.querySelector('#db-level-values');
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
      ? t('einstellungen.verschluesselung.ersetzt', { stufe: STUFEN[i][1] })
      : hinweis(i) === STUFEN[i][2] ? t('einstellungen.verschluesselung.stufeHinweis', { stufe: STUFEN[i][1], hinweis: STUFEN[i][2] }) : hinweis(i);
    // Klein darunter: was jetzt gilt — und, sobald etwas gewählt ist,
    // was danach gilt.
    const [, , , it, mib, p] = STUFEN[i];
    werte.innerHTML = `${t('einstellungen.verschluesselung.jetzt', { werte: kdfWerte(info.iterations, info.memoryMib, info.parallelism) })}${
      offen() ? `<br>${t('einstellungen.verschluesselung.danach', { werte: kdfWerte(it, mib, p) })}` : ''}`;
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
        einzeln.textContent = `${info.format} · ${info.cipher} · ${info.kdf}`;
      }
      banner(t('einstellungen.verschluesselung.geaendert'), 'success');
    } catch (err) {
      banner(t('einstellungen.allgemein.nichtGespeichert', { fehler: err.message }), 'error', 6000);
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
      modifiedEl.textContent = ` · ${t('einstellungen.datenbank.geaendert', { datum: new Date(ms).toLocaleString(gebiet(), { dateStyle: 'medium', timeStyle: 'short' }) })}`;
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
      <strong>${t('einstellungen.allgemein.nichtVerfuegbar')}</strong><small>${esc(err.message)}</small></div></div>`;
    return;
  }

  const eingerichtet = status.installed.length
    ? status.installed.join(', ')
    : t('einstellungen.browser.keinerEingetragen');

  const verknuepft = status.associations.length
    ? status.associations.map(name => `
        <div class="setting">
          <div class="setting-label"><strong>${esc(name)}</strong><small>${t('einstellungen.browser.verknuepft')}</small></div>
          <div class="setting-control">
            <button type="button" class="button" data-forget="${esc(name)}">${t('einstellungen.browser.trennen')}</button>
          </div>
        </div>`).join('')
    : `<div class="setting"><div class="setting-label">
         <small>${t('einstellungen.browser.keinerVerknuepft')}</small></div></div>`;

  const guard = settings.get('browser.guard', 'identify');
  const grace = Number(settings.get('browser.graceSeconds', 60));
  const unlockOnConnect = settings.get('browser.unlockOnConnect', false) === true;

  card.innerHTML = `
    <div class="setting">
      <div class="setting-label">
        <strong>${t('einstellungen.stufe.titel')}</strong>
        <small>${t('einstellungen.browser.stufeHinweis')}</small>
      </div>
      <div class="setting-control">
        <div class="group-radio" id="browser-guard">
          ${[['never', t('einstellungen.stufe.nichts')], ['confirm', t('einstellungen.stufe.bestaetigen')], ['identify', t('einstellungen.stufe.legitimieren')]]
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
        <strong>${t('einstellungen.frist.titel')}</strong>
        <small>${t('einstellungen.browser.fristHinweis')}</small>
      </div>
      <div class="setting-control">
        <select id="browser-grace" name="browser.graceSeconds" data-sp-picker data-sp-search="false">
          ${[[0, t('einstellungen.frist.jedesMal')], [30, t('einstellungen.frist.sek30')], [60, t('einstellungen.frist.min1')], [300, t('einstellungen.frist.min5')], [900, t('einstellungen.frist.min15')]]
            .map(([wert, label]) => `<option value="${wert}" ${grace === wert ? 'selected' : ''}>${label}</option>`).join('')}
        </select>
      </div>
    </div>
    <div class="setting">
      <div class="setting-label">
        <strong>${t('einstellungen.browser.beimStart')}</strong>
        <small>${t('einstellungen.browser.beimStartHinweis')}</small>
      </div>
      <div class="setting-control">
        <input type="checkbox" data-shape="toggle" id="browser-unlock-on-connect"
          aria-label="${t('einstellungen.browser.beimStart')}" ${unlockOnConnect ? 'checked' : ''}>
      </div>
    </div>
    <div class="setting" data-stacked>
      <div class="setting-label">
        <strong>${t('einstellungen.browser.erweiterung')}</strong>
        <small>${t('einstellungen.browser.erweiterungHinweis')}</small>
      </div>
      <div class="setting-control store-buttons">
        ${BROWSER_STORES.map((b, i) => `<button type="button" class="button" data-store="${i}"><span class="msr">open_in_new</span>&nbsp;${esc(b.name)}</button>`).join('')}
      </div>
    </div>
    <div class="setting">
      <div class="setting-label">
        <strong>${t('einstellungen.browser.eingetragen')}</strong>
        <small>${esc(eingerichtet)}</small>
        <small>${t('einstellungen.browser.eingetragenHinweis')}</small>
      </div>
      <div class="setting-control">
        <button type="button" class="button" id="btn-browser-install">${t('einstellungen.browser.einrichten')}</button>
        <button type="button" class="button" id="btn-browser-remove">${t('einstellungen.browser.entfernen')}</button>
      </div>
    </div>
    ${verknuepft}
    <div class="setting">
      <div class="setting-label">
        <strong>${t('einstellungen.browser.kanal')}</strong>
        <small>${status.listening ? t('einstellungen.android.aktiv') : t('einstellungen.browser.nichtAktiv')} — <code>${esc(status.socket)}</code></small>
      </div>
    </div>`;

  card.querySelectorAll('[name="browser.guard"]').forEach(el =>
    el.addEventListener('change', async () => {
      await settings.set('browser.guard', el.value, { silent: true });
      banner({
        never: t('einstellungen.browser.stufeNichts'),
        confirm: t('einstellungen.stufe.bestaetigenMeldung'),
        identify: t('einstellungen.browser.stufeLegitimieren')
      }[el.value], el.value === 'never' ? 'warning' : 'success', 5000);
    }));

  // Der Kern liest die Frist bei jeder Anfrage aus den Einstellungen.
  card.querySelector('#browser-grace')?.addEventListener('change', async ev => {
    await settings.set('browser.graceSeconds', Number(ev.target.value), { silent: true });
  });

  // Der Kern liest den Schalter, wenn sich ein Browser meldet.
  card.querySelector('#browser-unlock-on-connect')?.addEventListener('change', async ev => {
    await settings.set('browser.unlockOnConnect', ev.target.checked, { silent: true });
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
        banner(t('einstellungen.browser.getrennt'), 'success');
        renderBrowserSection();
      } catch (err) {
        banner(t('einstellungen.browser.trennenFehler', { fehler: err.message }), 'error');
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
export async function showBrowserSetupPage() {
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
        <h2>${t('einstellungen.browserStart.titel')}</h2>
        <p class="lock-sub">${t('einstellungen.browserStart.text')}</p>

        <div class="settings-card">
          <div class="setting">
            <div class="setting-label"><strong>${t('einstellungen.browserStart.schritt1')}</strong>
              <small>${t('einstellungen.browserStart.schritt1Text')}</small>
              <small>${found.length
                ? t('einstellungen.browserStart.gefunden', { liste: found.map(b => `${esc(b)}${done.includes(b) ? ' ✓' : ''}`).join(' · ') })
                : t('einstellungen.browserStart.keinBrowser')}</small></div>
            <div class="setting-control">${found.length && done.length === found.length
              ? `<span class="setting-state" data-tone="ok"><span class="msr">check_circle</span>${t('einstellungen.browserStart.erledigt')}</span>`
              : `<button type="button" class="button hightlight" id="bs-install" ${found.length ? '' : 'disabled'}>${t('einstellungen.browserStart.eintragen')}</button>`}</div>
          </div>
          <div class="setting" data-stacked>
            <div class="setting-label"><strong>${t('einstellungen.browserStart.schritt2')}</strong>
              <small>${t('einstellungen.browserStart.schritt2Text')}</small></div>
            <div class="setting-control store-buttons">
              ${BROWSER_STORES.map((b, i) => `<button type="button" class="button" data-store="${i}"><span class="msr">open_in_new</span>&nbsp;${esc(b.name)}</button>`).join('')}
            </div>
          </div>
          <div class="setting">
            <div class="setting-label"><strong>${t('einstellungen.browserStart.schritt3')}</strong>
              <small>${t('einstellungen.browserStart.schritt3Text')}</small></div>
          </div>
        </div>

        <div class="lock-actions">
          <button type="button" class="button hightlight" data-shape="full" id="bs-done"><span class="msr">check</span>&nbsp;${t('einstellungen.allgemein.weiter')}</button>
          <button type="button" class="button" data-shape="full" id="bs-later">${t('einstellungen.allgemein.spaeter')}</button>
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
      // i18n: einstellungen.browser.eingerichtetMeldung einstellungen.browser.entferntMeldung
      banner(t(install ? 'einstellungen.browser.eingerichtetMeldung' : 'einstellungen.browser.entferntMeldung', { liste: ok.join(', ') }),
        'success', 8000);
    } else if (!failed.length) {
      banner(t('einstellungen.browser.keinGefunden'), 'info');
    }

    for (const r of failed) {
      banner(`${r.browser}: ${r.note ?? t('einstellungen.browser.fehlgeschlagen')}`, 'warning', 8000);
    }

    renderBrowserSection();
  } catch (err) {
    banner(t('einstellungen.browser.einrichtenFehler', { fehler: err.message }), 'error', 6000);
  }
}

/**
 * Einstellungen als volle Seite — auch vom Sperrbildschirm aus.
 *
 * Es gibt nur diesen einen Bauplan. Ohne offene Datenbank wird der
 * Abschnitt „Diese Datenbank" per CSS ausgeblendet (`[data-needs-db]`),
 * sonst ändert sich nichts.
 */
export function openSettingsPage() {
  document.body.dataset.settingsOnly = 'true';
  $('#lockscreen').hidden = true;
  renderSettings();
  showView('settings');
}

export function closeSettingsPage() {
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

  // Sprache: speichern und neu laden, damit alles in der neuen Sprache entsteht.
  root.querySelector('[name="appearance.language"]')?.addEventListener('change', async ev => {
    await settings.set('appearance.language', ev.target.value, { silent: true });
    location.reload();
  });

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
    banner(t('einstellungen.allgemein.gespeichert'), 'success', 1600);
  }));

  root.querySelectorAll('[data-set]').forEach(el => el.addEventListener('change', async () => {
    const value = el.type === 'checkbox' ? el.checked : el.type === 'number' ? Number(el.value) : el.value;
    await settings.set(el.dataset.set, value);

    // Die Ruhezeit hütet der Kern, nicht das Fenster — er muss sie erfahren.
    if (el.dataset.set === 'unlock.autoLockMinutes' && !state.locked) {
      await vault.setAutoLock(Number(value) || 0);
    }
    if (el.dataset.set === 'names.fromWebsite' && value) autoRetitle();

    banner(t('einstellungen.allgemein.gespeichert'), 'success', 1600);
  }));

  root.querySelectorAll('[name="checks.automatic"]').forEach(el =>
    el.addEventListener('change', async () => {
      await settings.set('checks.automatic', el.value, { silent: true });
      updateSettingsPreview();
    }));

  root.querySelector('#btn-refresh-icons')?.addEventListener('click', async () => {
    await vault.fetchIcons(null, true);
    banner(t('einstellungen.eintraege.iconsAbruf'), 'success');
  });

  root.querySelector('#btn-adopt-titles')?.addEventListener('click', async () => {
    const withUrl = state.entries.filter(e => hostFromUrl(e.url));
    if (!withUrl.length) { banner(t('einstellungen.eintraege.keineUrl'), 'info'); return; }

    const res = await dialog({
      title: t('einstellungen.eintraege.uebernehmenTitel'),
      content: `${t('einstellungen.eintraege.uebernehmenText', { n: `<strong>${withUrl.length}</strong>` })}
                ${isTauri ? '' : `<br><br>${t('einstellungen.eintraege.uebernehmenBrowser')}`}`,
      confirmText: t('einstellungen.allgemein.uebernehmen'),
      cancelText: t('allgemein.knoepfe.abbrechen')
    });
    if (!(res?.submit ?? res)) return;
    await adoptTitles(withUrl);
  });

  root.querySelector('#btn-import-entries')?.addEventListener('click', () => importFromOtherApps());

  root.querySelector('#btn-export')?.addEventListener('click', () => {
    settings.downloadSettings();
    banner(t('einstellungen.export.exportiert'), 'success');
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
        banner(t('einstellungen.export.importiert'), 'success');
      } catch (err) {
        banner(t('einstellungen.export.nichtGelesen', { fehler: err.message }), 'error');
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
  root.querySelectorAll('[data-scroll]').forEach(btn => btn.addEventListener('click', () => springeZu(btn.dataset.scroll)));

  root.querySelector('#btn-empty-bin')?.addEventListener('click', emptyBin);

  root.querySelector('#btn-reset')?.addEventListener('click', async () => {
    let confirmed = false;
    try {
      const res = await dialog({
        title: t('einstellungen.export.zuruecksetzenTitel'),
        content: `<p>${t('einstellungen.export.zuruecksetzenText1')}</p>
          <p>${t('einstellungen.export.zuruecksetzenText2')}</p>`,
        confirmText: t('einstellungen.export.zuruecksetzenKnopf'),
        cancelText: t('allgemein.knoepfe.abbrechen')
      });
      confirmed = res?.submit ?? res === true;
    } catch {
      confirmed = false;
    }
    if (!confirmed) return;

    const spracheVorher = settings.get('appearance.language', 'auto');
    await settings.resetSettings();
    applyAppearance(settings.get('appearance', {}));
    state.expanded = new Set();
    renderSettings();
    banner(t('einstellungen.export.zurueckgesetzt'), 'success');
    // Die Sprache geht mit zurück — dann alles neu zeichnen.
    if (settings.get('appearance.language', 'auto') !== spracheVorher) location.reload();
  });
}

export function updateSettingsPreview() {
  const pre = document.getElementById('settings-preview');
  if (pre) pre.textContent = settings.exportSettings();
}
