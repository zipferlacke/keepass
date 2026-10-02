/**
 * entry.js — der Dialog für einen Eintrag.
 *
 * Ein Formular, zwei Gesichter: Als Zugang zeigt es Benutzer, Passwort,
 * Adresse und Einmalcode, als Dateiablage nur Name, Notiz und Anhänge.
 * Umgeschaltet wird oben; verworfen wird dabei nichts — gespeichert wird
 * am Ende in beiden Fällen dasselbe.
 *
 * Die Geheimnisse bleiben im Kern: Im Dialog steht nur eine Maske, und
 * erst beim Speichern wandert ein geänderter Wert als Token hinüber.
 *
 * Dazu gehören die Anhänge: einlesen, ablegen, umbenennen, ansehen — die
 * Vorschau im Vollbild steht am Ende der Datei.
 */

import * as vault from '../data/vault.js';
import * as settings from '../data/settings.js';
import * as qr from '../data/qr.js';
import * as preview from '../data/preview.js';
import { parseOtpauth, buildOtpauth } from '../data/totp.js';
import { passwordStrength as localStrength, checkPwnedByHash } from '../data/security.js';
import { loadAttachments, sizeOfDataUrl, formatBytes, downloadWithWarning, generatePassword } from '../data/attachments.js';
import { copyPlain, scheduleClipboardClear } from '../ui/clipboard.js';
import { dialog, banner, closeHostDialog, selectPicker, zurueckZu, renderQrCode } from '../ui/libs.js';
import { resolvedColor } from '../core/theme.js';
import { state, esc, SECRET_MASK } from '../core/state.js';
import { markUsed, byId, isFileEntry, formatDate } from '../core/entries.js';
import { zeichne, renderAll, refreshFromVault } from '../core/render.js';
import { isTauri, listen } from '../core/platform.js';

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
export async function openEntryDialog(id, prefill = {}, { mode = null, files = [], zurueck = null } = {}) {
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
            <select id="fld-algorithm" name="algorithm" data-sp-picker data-sp-search="false">
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
        ${e.passkey ? `<div class="setting" style="padding:0;border:none">
          <div class="setting-label"><strong>${esc(e.passkeySite || 'Passkey')}</strong>
            <small>${e.passkeyUser ? `Konto: ${esc(e.passkeyUser)} · ` : ''}Anmelden ohne Passwort — der geheime Schlüssel liegt nur in dieser Datenbank.</small></div>
        </div>`
        : `<p class="dlg-note" style="margin:0">Einen Passkey legst du direkt beim Dienst an („Passkey erstellen“). Browser-Erweiterung oder Android
            fragen dann WKeePass, und er landet von selbst in einem Eintrag.</p>`}
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
    onBack: zurueckZu(zurueck),
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
    passkey: Boolean(e.passkey),
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
  renderAll({ ohne: ['einstellungen'] });
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
export async function showQrDialog(uri, title) {
  await dialog({
    title: `QR-Code: ${esc(title)}`,
    content: `
      <div class="qr-output" id="qr-export"><p class="empty-state">Wird erzeugt …</p></div>
      <p class="dlg-note">Mit einer Authenticator-App abscannen. Der Code enthält das Secret im Klartext — nicht weitergeben und nicht abfotografieren lassen.</p>`,
    // Nichts zu entscheiden, also keine Fußzeile.
    confirmText: null,
    cancelText: 'Schließen',
    // Ohne Fußzeile führt nur das Kreuz oben heraus.
    barRight: { icon: 'close', title: 'Schließen', action: 'cancel' },
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

/**
 * Kamera-Scan in einem eigenen Dialog.
 *
 * Kein „Fertig" zum Drücken: Ist ein Code erkannt, leuchtet der Rahmen auf,
 * und der Dialog schließt sich von selbst — weiter geht es dort, wo der
 * Code hingehört. Abgebrochen wird oben rechts mit dem Kreuz; eine Fußzeile
 * mit einem einzigen Knopf darin wäre hier nur verschenkte Höhe.
 */
export async function scanWithCamera({ zurueck = null } = {}) {
  let controller = null;
  let resolved = null;

  await dialog({
    title: 'QR-Code scannen',
    content: `<div class="qr-scanner">
        <div class="qr-frame">
          <video id="qr-video" muted playsinline></video>
          <div class="qr-sucher"></div>
          <div class="qr-check"><span class="msr">check</span></div>
        </div>
        <p class="qr-hint" id="qr-hint">Code in den Rahmen halten</p>
        <button type="button" class="button" id="qr-photo"><span class="msr">photo_camera</span>&nbsp;Klappt nicht? Foto aufnehmen</button>
      </div>`,
    confirmText: null,
    cancelText: 'Abbrechen',
    // Ohne Fußzeile führt nur das Kreuz oben heraus.
    barRight: { icon: 'close', title: 'Abbrechen', action: 'cancel' },
    onBack: zurueckZu(zurueck),
    onInsert: () => queueMicrotask(async () => {
      const video = document.getElementById('qr-video');
      const hint = document.getElementById('qr-hint');
      if (!video) return;

      // Rückfallweg für dichte Codes: ein richtiges Foto, scharf gestellt
      // von der Kamera-App — und dann genauso weiter wie beim Treffer.
      document.getElementById('qr-photo')?.addEventListener('click', () => {
        // Die Kamera-App braucht die Kamera für sich — Vorschau vorher aus.
        controller?.stop();
        const input = document.createElement('input');
        input.type = 'file';
        input.accept = 'image/*';
        input.setAttribute('capture', 'environment');
        input.addEventListener('change', async () => {
          const file = input.files?.[0];
          if (!file) return;
          if (hint) hint.textContent = 'Foto wird ausgewertet …';
          try {
            resolved = await qr.scanPhoto(file);
            controller?.stop();
            video.closest('.qr-scanner')?.classList.add('found');
            navigator.vibrate?.(40);
            await new Promise(r => setTimeout(r, 650));
            closeHostDialog(video, true);
          } catch (err) {
            if (hint) hint.textContent = err.message;
          }
        });
        input.click();
      });

      try {
        controller = await qr.scanCamera(video);
        const found = await controller.promise;
        if (resolved) return;          // schon über das Foto erkannt
        resolved = found;
        if (hint) hint.textContent = 'Erkannt';
        video.closest('.qr-scanner')?.classList.add('found');
        navigator.vibrate?.(40);
        // Das Aufleuchten kurz stehen lassen, dann von selbst weiter.
        await new Promise(r => setTimeout(r, 650));
        closeHostDialog(video, true);
      } catch (err) {
        if (hint && err.message !== 'abgebrochen') hint.textContent = err.message.startsWith("Auswertung") ? err.message : `Kamera nicht verfügbar: ${err.message}`;
      }
    })
  });

  controller?.stop();
  if (!resolved) throw new Error('abgebrochen');
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
export async function addStagedAttachments(picked = []) {
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
export async function bindFileDrops() {
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

export function renderAttachments() {
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
   Ein userDialog im Vollbild: oben links die Knöpfe, in der Mitte der
   Dateiname (der zugleich der Knopf zum Umbenennen ist), rechts das Kreuz,
   darunter die Datei auf der ganzen Fläche. Keine Fußzeile — es gibt nichts
   zu bestätigen, und die Höhe gehört der Datei. Breite, Höhe und Rundung
   sind Variablen der Bibliothek; `#file-viewer` setzt sie auf Vollbild.
   Als modaler Dialog liegt die Vorschau über dem offenen Eintrag, und
   Escape schließt nur sie.

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

export async function openAttachmentViewer(att, { edit = false } = {}) {
  if (!att) return;
  if (state.dialogEntryId) markUsed(state.dialogEntryId);

  let viewer = null;          // der Dialog, sobald er im Dokument steht
  let cleanup = () => {};
  let closed = false;
  let editor = null;          // Textfeld, solange bearbeitet wird
  let original = '';

  const $v = sel => viewer?.querySelector(sel);
  // Die Knöpfe oben links in der Reihenfolge, in der sie unten angemeldet
  // sind: 0 Bearbeiten, 1 Anzeigen, 2 Übernehmen, 3 Herunterladen.
  const knopf = i => viewer?.querySelector(`[data-bar="left:${i}"]`);
  const body = () => $v('.file-viewer-body');
  const nameInput = () => $v('.file-viewer-rename');

  const editable = () => EDITABLE_KINDS.has(preview.kindOf(att));
  const dirty = () => Boolean(editor) && editor.value !== original;

  /** Knöpfe passend zur Ansicht: Bearbeiten — oder Anzeigen und Speichern. */
  const showButtons = () => {
    if (!viewer) return;
    knopf(0).hidden = Boolean(editor) || !editable();
    knopf(1).hidden = !editor;
    knopf(2).hidden = !editor;
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
    body().innerHTML = '<p class="empty-state">Wird geladen …</p>';
    const release = await preview.renderPreview(body(), att);
    if (closed) release(); else cleanup = release;
  };

  const showEditor = async () => {
    if (editor || !editable()) return;
    original = await preview.asText(att);
    cleanup();
    cleanup = () => {};
    body().innerHTML = '';
    editor = document.createElement('textarea');
    editor.className = 'file-editor';
    editor.spellcheck = false;
    editor.value = original;
    body().append(editor);
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

  /**
   * Das Kreuz oben rechts fragt erst, dann schließt es. Deshalb hat es eine
   * eigene Funktion statt der Aktion 'cancel' — und schließt am Ende selbst
   * über `uDFinish`, sonst bliebe das Versprechen offen.
   */
  const requestClose = async () => {
    if (await confirmLeave()) viewer.uDFinish('cancel');
  };

  const startRename = () => {
    const feld = nameInput();
    feld.value = att.name;
    $v('.file-viewer-name').hidden = true;
    feld.hidden = false;
    feld.focus();
    // Nur den Namen vor der Endung markieren, wie im Dateimanager.
    const dot = att.name.lastIndexOf('.');
    feld.setSelectionRange(0, dot > 0 ? dot : att.name.length);
  };

  const finishRename = async (apply) => {
    const feld = nameInput();
    if (feld.hidden) return;
    const next = feld.value.trim();
    feld.hidden = true;
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

  await dialog({
    id: 'file-viewer',
    // Der Titel ist der Dateiname und zugleich der Knopf zum Umbenennen.
    title: `<span class="file-viewer-title">
        <button type="button" class="file-viewer-name" data-viewer-rename title="Umbenennen"><strong></strong><span class="msr">edit</span></button>
        <input type="text" class="file-viewer-rename" hidden aria-label="Dateiname">
      </span>`,
    content: `<div class="file-viewer-body"></div>`,
    confirmText: null,
    cancelText: 'Schließen',
    barLeft: [
      { icon: 'edit_note', title: 'Bearbeiten', onClick: showEditor },
      { icon: 'visibility', title: 'Anzeigen', onClick: async () => { if (await confirmLeave()) showPreview(); } },
      { icon: 'check', title: 'Speichern', onClick: saveEdit },
      { icon: 'download', title: 'Herunterladen', onClick: async () => { if (await confirmLeave()) downloadWithWarning(att); } }
    ],
    barRight: { icon: 'close', title: 'Schließen', onClick: requestClose },
    onInsert: id => {
      viewer = document.getElementById(String(id));

      // Escape: erst das Umbenennen abbrechen, sonst wie das Kreuz. Der
      // eigene Horcher hängt vor dem der Bibliothek und hält sie an —
      // sonst wäre der Dialog zu, bevor nach den Änderungen gefragt ist.
      viewer.addEventListener('cancel', ev => {
        ev.preventDefault();
        ev.stopImmediatePropagation();
        if (!nameInput().hidden) finishRename(false);
        else requestClose();
      });
      viewer.addEventListener('close', () => { closed = true; cleanup(); });

      $v('[data-viewer-rename]').addEventListener('click', startRename);
      nameInput().addEventListener('keydown', ev => {
        if (ev.key === 'Enter') { ev.preventDefault(); finishRename(true); }
      });
      nameInput().addEventListener('blur', () => finishRename(true));

      showName();
      showButtons();
      // Der Inhalt kommt, sobald der Dialog steht.
      queueMicrotask(() => (edit && editable()) ? showEditor() : showPreview());
    }
  });
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
export async function createEmptyFile() {
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
          <select id="fld-new-file-type" name="newFileType" data-sp-picker data-sp-search="false">
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
