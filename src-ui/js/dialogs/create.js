/**
 * create.js — Neu anlegen.
 *
 * Der Dialog hinter dem „+": Eintrag, Dateien, Ordner, Import, QR-Code
 * scannen oder aus einem Bild lesen — und was danach mit einem gelesenen
 * Code passiert (TOTP einem Eintrag zuordnen, Sammelexport übernehmen).
 */

import * as vault from '../data/vault.js';
import { parseOtpauth } from '../data/totp.js';
import * as qr from '../data/qr.js';
import { parseImport, itemsFromCsv, CSV_FIELDS } from '../data/import.js';
import * as pick from '../ui/multiselect.js';
import { dialog, banner, closeHostDialog, zurueckZu } from '../ui/libs.js';
import { state, $, esc } from '../core/state.js';
import { renderAll, refreshFromVault } from '../core/render.js';
import { openFolderDialog } from './folder.js';
import { openEntryDialog, scanWithCamera } from './entry.js';

export async function startCreation() {
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
export async function handleScan(value) {
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

export async function importFromOtherApps({ zurueck = null } = {}) {
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
