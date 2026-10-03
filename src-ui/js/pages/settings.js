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
            <input type="number" inputmode="numeric" min="1" max="180" data-set-db="expiryWarnDays" name="db.expiryWarnDays" value="${dbSettings.expiryWarnDays ?? 14}">
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
          <div class="setting-control"><input type="number" inputmode="numeric" min="1" max="120" data-set="unlock.autoLockMinutes" name="unlock.autoLockMinutes" value="${s.unlock?.autoLockMinutes ?? 5}"></div>
        </div>
        <div class="setting">
          <div class="setting-label"><strong>Zwischenablage leeren</strong><small>Sekunden nach dem Kopieren</small></div>
          <div class="setting-control"><input type="number" inputmode="numeric" min="0" max="300" data-set="unlock.clipboardClearSeconds" name="unlock.clipboardClearSeconds" value="${s.unlock?.clipboardClearSeconds ?? 30}"></div>
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
          <div class="setting-control"><input type="number" inputmode="numeric" min="1" max="180" data-set="checks.expiryWarnDays" name="checks.expiryWarnDays" value="${s.checks?.expiryWarnDays ?? 14}"></div>
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
          <div class="setting-label"><strong>Auf Standard zurücksetzen</strong><small>Nur die Einstellungen — Datenbanken, PIN und Browser-Verknüpfungen bleiben</small></div>
          <div class="setting-control"><button type="button" class="button" id="btn-reset">Zurücksetzen</button></div>
        </div>
      </div>
    </div>

    <details class="settings-group settings-raw">
      <summary class="section-label">Aktuelle Konfiguration (settings.json)</summary>
      <div class="settings-card">
        <pre id="settings-preview">${esc(settings.exportSettings())}</pre>
      </div>
    </details>

    <p class="app-version" id="app-version">WKeePass</p>`
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
    el.textContent = 'WKeePass · Demo im Browser';
  }
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
export async function showAndroidSetup() {
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
/** Wie im Kern (database.rs): Wert, Name, Hinweis, Durchgänge, MiB, Fäden. */
export const STUFEN = [
  ['schnell', 'Schnell', 'Öffnet zügig, auch auf älteren Geräten', 5, 32, 2],
  ['zuegig', 'Zügig', 'Etwas mehr Schutz, kaum langsamer', 8, 48, 2],
  ['standard', 'Standard', 'Guter Mittelweg — Empfehlung', 10, 64, 4],
  ['erhoeht', 'Erhöht', 'Mehr Schutz, öffnet etwas langsamer', 14, 128, 4],
  ['stark', 'Stark', 'Bestmöglicher Schutz, spürbar längeres Öffnen', 20, 256, 4]
];

/** Auf der Skala beschriftet sind nur diese — die beiden dazwischen nicht. */
const BENANNT = new Set(['schnell', 'standard', 'stark']);

/** „10 Durchgänge · 64 MiB · 4 Fäden" */
const kdfWerte = (it, mib, p) => `${it} Durchgänge · ${mib} MiB · ${p} ${p === 1 ? 'Faden' : 'Fäden'}`;

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
    title: 'Verschlüsselungsstärke',
    content: `
      <p>Aus dem Master-Passwort wird erst ein Schlüssel abgeleitet — absichtlich langsam, mit
      Argon2. Jeder Rateversuch eines Angreifers muss diese Arbeit genauso leisten.</p>
      <dl class="kdf-begriffe">
        <dt>Durchgänge</dt>
        <dd>Wie oft Argon2 über den Speicher rechnet. Doppelt so viele dauern doppelt so lange.</dd>
        <dt>Speicher (MiB)</dt>
        <dd>Wie viel Arbeitsspeicher jeder Versuch belegt (1 MiB ≈ 1 MB). Das bremst Angriffe mit
        Grafikkarten am stärksten, weil dort Speicher knapp ist.</dd>
        <dt>Fäden</dt>
        <dd>Wie viele Prozessorkerne gleichzeitig rechnen. Am Schutz ändert das nichts — es macht
        nur das Öffnen auf deinem Gerät schneller.</dd>
        <dt>Eigene Einstellung</dt>
        <dd>Andere Apps und ältere Dateien bringen eigene Werte mit, etwa 50 Durchgänge mit nur
        1 MiB. Die App zeigt dann die Stufe, die am nächsten liegt, und lässt die Werte stehen, bis
        du eine Stufe übernimmst.</dd>
      </dl>`,
    confirmText: null,
    cancelText: 'Schließen',
    barRight: { icon: '<span class="msr">close</span>', title: 'Schließen', action: 'cancel' }
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
    ? `Eigene Einstellung, etwa aus einer anderen App — liegt ungefähr bei „${STUFEN[i][1]}“. Eine Stufe übernehmen ersetzt sie.`
    : STUFEN[i][2];
  let regler = null;

  card.innerHTML = `
    <div class="setting db-name-row">
      <div class="setting-label">
        <strong>Name der Datenbank</strong>
        <small>${path ? esc(pfadLabel(path, eintrag?.label)) : 'Steht in der Datei'}<span id="db-modified"></span></small>
      </div>
      <div class="setting-control">
        <input type="text" id="db-name" value="${esc(info.name)}" placeholder="Passwörter"
               aria-label="Name der Datenbank" ${info.readOnly ? 'disabled' : ''}>
      </div>
    </div>

    <div class="setting" data-stacked>
      <div class="setting-label">
        <strong>Verschlüsselungsstärke
          <button type="button" class="info-btn" id="kdf-info" title="Was bedeuten die Werte?"
                  aria-label="Was bedeuten die Werte?"><span class="msr">info</span></button></strong>
        <small>Wie lange das Ableiten des Schlüssels dauert — für dich einmal beim Öffnen,
        für einen Angreifer bei jedem Rateversuch</small>
      </div>
      <div class="setting-control kdf-slider">
        <input type="range" id="db-level" min="0" max="${STUFEN.length - 1}" step="1" value="${stufe}"
               aria-label="Verschlüsselungsstärke" ${info.readOnly ? 'disabled' : ''}>
        <div class="kdf-labels">
          ${STUFEN.map(([wert, name], i) => `<button type="button" data-stufe="${i}" ${i === stufe ? 'aria-current="true"' : ''}
            ${BENANNT.has(wert) ? '' : 'data-zwischen'} title="${name}"
            ${info.readOnly ? 'disabled' : ''}>${BENANNT.has(wert) ? name : '·'}</button>`).join('')}
        </div>
        <small class="kdf-note" id="db-level-note"></small>
        <small class="kdf-values" id="db-level-values"></small>
        <small class="kdf-values" id="db-details">${esc(info.format)} · ${esc(info.cipher)} · ${esc(info.kdf)}</small>
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
`;

  card.querySelector('#btn-versions')?.addEventListener('click', () => openVersionsDialog());
  card.querySelector('#kdf-info')?.addEventListener('click', kdfErklaeren);

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
      ? `Ersetzt die eigene Einstellung durch „${STUFEN[i][1]}“.`
      : hinweis(i) === STUFEN[i][2] ? `${STUFEN[i][1]}: ${STUFEN[i][2]}` : hinweis(i);
    // Klein darunter: was jetzt gilt — und, sobald etwas gewählt ist,
    // was danach gilt.
    const [, , , it, mib, p] = STUFEN[i];
    werte.innerHTML = `Jetzt: ${kdfWerte(info.iterations, info.memoryMib, info.parallelism)}${
      offen() ? `<br>Danach: ${kdfWerte(it, mib, p)}` : ''}`;
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
      modifiedEl.textContent = ` · geändert ${new Date(ms).toLocaleString('de-DE', { dateStyle: 'medium', timeStyle: 'short' })}`;
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

  root.querySelector('#btn-empty-bin')?.addEventListener('click', emptyBin);

  root.querySelector('#btn-reset')?.addEventListener('click', async () => {
    let confirmed = false;
    try {
      const res = await dialog({
        title: 'Einstellungen zurücksetzen',
        content: `<p>Darstellung, Entsperren, Prüfungen, Browser und Android gehen auf die
          Standardwerte zurück.</p>
          <p>Es bleiben: die Datenbank selbst, die Liste deiner Datenbanken samt ihren eigenen
          Einstellungen, die App-PIN und die Verknüpfungen mit dem Browser.</p>`,
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

export function updateSettingsPreview() {
  const pre = document.getElementById('settings-preview');
  if (pre) pre.textContent = settings.exportSettings();
}
