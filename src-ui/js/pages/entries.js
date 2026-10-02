/**
 * entries.js — die Seite mit den Einträgen.
 *
 * Eine Tabelle, zwei Gesichter: Einträge mit Benutzer, Code und Sicherheit,
 * oder Dateien mit Art und Größe. Welche Spalten kommen, entscheidet der
 * Zusammenhang (`COLUMNS`); gruppiert wird nach Ordnern, und die Gruppen
 * merken sich, was aufgeklappt war.
 *
 * Dazu gehört alles, was an einer Zeile hängt: das Kontextmenü (Rechtsklick
 * am Rechner, drei Punkte am Handy), die Mehrfachauswahl mit der Leiste
 * unten, das Verschieben per Ziehen und das Nachholen fehlender Titel von
 * der Website.
 */

import * as vault from '../data/vault.js';
import * as settings from '../data/settings.js';
import * as pick from '../ui/multiselect.js';
import { enableDragMove } from '../ui/dragmove.js';
import { dialog, banner, closeHostDialog, tableview, selectPicker } from '../ui/libs.js';
import { copyPlain, scheduleClipboardClear } from '../ui/clipboard.js';
import { avatarMarkup, hostFromUrl } from '../core/icons.js';
import { isTauri, isMobile, invoke } from '../core/platform.js';
import { state, $, $$, esc, SECRET_MASK, VIEW_TITLES } from '../core/state.js';
import { liveEntries, visibleEntries, expiryState, byId, hasFiles, isFileEntry,
         markUsed, formatDate } from '../core/entries.js';
import { seite, zeichne, renderAll, refreshFromVault, nachStrukturaenderung } from '../core/render.js';
import { loadAttachments, formatBytes, saveAttachment, downloadWithWarning } from '../data/attachments.js';
import { openEntryDialog, openAttachmentViewer } from '../dialogs/entry.js';
import { openFolderDialog } from '../dialogs/folder.js';
import { tickTotp } from './totp.js';
import { captureFields } from '../ui/formular.js';

/* ---------- Eintrags-Zeile ---------- */
export function wireEntryRows(root, { select = true } = {}) {
  root.querySelectorAll('[data-open]').forEach(el =>
    el.addEventListener('click', () => openEntryDialog(el.dataset.open)));

  // In der Tabelle öffnet ein Klick auf die Zeile den Eintrag —
  // außer man trifft einen der Knöpfe oder Marker.
  // Erst die Auswahl: Sie entscheidet mit, ob ein Klick öffnen darf.
  // Auswählen und gemeinsam Verschieben nur in der Passwortliste — in
  // Befunden und Übersicht gibt es nichts zu ordnen.
  if (select) pick.wireSelection(root, id => vault.getEntry(id)?.folder ?? '');
  else root.addEventListener('dragstart', ev => ev.preventDefault());

  root.querySelectorAll('tr[data-id]').forEach(row => {
    row.addEventListener('click', ev => {
      if (ev.target.closest('button, .marker')) return;
      if (select && pick.selectionActive()) return;
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


/* =========================================================
   Kontextmenü einer Zeile
   ========================================================= */

let openMenu = null;

export function closeContextMenu() {
  openMenu?.remove();
  openMenu = null;
}

/**
 * Baut das Kontextmenü passend zu dem, worauf geklickt wurde.
 * „Eintrag erstellen“ und „Ordner erstellen“ sind immer dabei; je nach
 * Ziel kommen die Aktionen für Eintrag oder Ordner davor.
 */
export function showContextMenu(x, y, { entryId = null, folderPath = null } = {}) {
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
      renderAll({ ohne: ['einstellungen'] });
      banner('Wiederhergestellt.', 'success');
      return;
    }

    case 'purge': {
      // Der Eintrag liegt schon im Papierkorb — löschen heißt hier endgültig.
      await vault.deleteEntry(entryId);
      await vault.commit();
      await refreshFromVault();
      renderAll({ ohne: ['einstellungen'] });
      banner('Endgültig gelöscht.', 'success');
      return;
    }

    case 'empty-bin': {
      const removed = await vault.emptyRecycleBin();
      await vault.commit();
      await refreshFromVault();
      renderAll({ ohne: ['einstellungen'] });
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
      return nachStrukturaenderung('Ordner gelöscht.');
    }

    default:
      return runRowAction(action, entryId);
  }
}

export async function runRowAction(action, id) {
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
      await vault.fetchIcons([entry.id], true);
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
      return nachStrukturaenderung('Eintrag gelöscht.');
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

/**
 * Steht als Name nur eine Adresse da — „https://login.example.com/…“,
 * „www.example.com“ oder genau der Hostname? So legen Browser-Erweiterung,
 * Autofill und manche Importe Einträge an.
 */
function nameIsAddress(e) {
  const name = String(e.name ?? '').trim();
  if (!name || name === 'Ohne Namen') return true;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(name) || /^www\./i.test(name)) return true;
  const host = hostFromUrl(e.url);
  if (host && [host, host.replace(/^www\./, '')].includes(name.toLowerCase())) return true;
  return /^[\w-]+(\.[\w-]+)+(\/\S*)?$/.test(name) && !/\s/.test(name) && Boolean(hostFromUrl(name));
}

/**
 * Benennt Einträge, deren Name nur eine Adresse ist, nach ihrem Dienst —
 * im Hintergrund, abschaltbar in den Einstellungen. Jeder Eintrag wird je
 * Sitzung nur einmal versucht, auch wenn die Seite nicht antwortet.
 */
const retitleTried = new Set();

let retitling = false;

export async function autoRetitle() {
  if (retitling || state.locked || !isTauri || !settings.get('names.fromWebsite', true)) return;
  const due = state.entries.filter(e => !e.recycled && !retitleTried.has(e.id) && nameIsAddress(e)
    && hostFromUrl(e.url || e.name));
  if (!due.length) return;

  retitling = true;
  let changed = 0;
  try {
    for (const e of due) {
      retitleTried.add(e.id);
      const url = e.url || e.name;
      const title = await fetchTitle(url);
      if (state.locked) return;
      if (!title || title === e.name) continue;
      await vault.saveEntry({ ...e, name: title, url: e.url || url });
      changed++;
    }
  } catch (err) {
    console.warn('Namen übernehmen:', err);
  } finally {
    retitling = false;
  }

  if (!changed || state.locked) return;
  await vault.commit();
  await refreshFromVault();
  renderAll({ ohne: ['einstellungen'] });
}

export async function adoptTitles(entries) {
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
  renderAll({ ohne: ['einstellungen'] });
  banner(`${changed} Name${changed === 1 ? '' : 'n'} übernommen.`, 'success');
}

/* ---------- Einträge ---------- */

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
  files: { icon: 'folder_zip', label: 'Dateien' }
};

function renderLegend() {
  const filter = KIND_FILTERS[state.kindFilter];
  // Die Dateiansicht hat keine Passwort-Ampel — nur der Filter zum Aufheben.
  const files = state.kindFilter === 'files';

  $('#legend').innerHTML = files ? `
    <button type="button" class="tag kind-filter" id="kind-filter-clear" aria-pressed="true" title="Zurück zu allen Einträgen">
      <span class="msr">${filter.icon}</span>${filter.label}<span class="msr">close</span></button>` : `
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
    $('#app-title').textContent = VIEW_TITLES.passwords;
    renderPasswords();
  });
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
  const box = opts.drag && pick.selectionActive()
    ? `<td class="pick-cell"><span class="pick-box ${pick.isSelected(e.id) ? 'on' : ''}"><span class="msr">${
        pick.isSelected(e.id) ? 'check_box' : 'check_box_outline_blank'}</span></span></td>`
    : '';

  // Gelöschte bleiben sichtbar, werden aber als das kenntlich gemacht,
  // was sie sind — und bei den Auswertungen ausgelassen.
  const recycled = e.recycled ? ' data-recycled title="Liegt im Papierkorb"' : '';
  // Ziehen nur in der Passwortliste — in Befunden und Übersicht hat
  // Umsortieren keinen Sinn.
  const drag = opts.drag ? ` data-drag-id="entry:${e.id}" data-drag-label="${esc(e.name)}"` : '';
  return `<tr data-id="${e.id}"${drag}${recycled}>${box}${cols.map(c => cellHtml(c, e, opts)).join('')}</tr>`;
}

function headerHtml(cols, sortable, pickable) {
  const box = pickable && pick.selectionActive() ? '<th class="pick-cell"></th>' : '';
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
function tableHtml(list, { variant = 'full', sortable = false, search = false, folders = false } = {}) {
  const cols = COLUMNS[variant] ?? COLUMNS.full;
  const iconsOn = settings.get('icons.download', true);

  // Nach Ordnern gruppiert: je Ebene eine versteckte Spalte hinten dran.
  const levels = folders ? Math.max(1, ...list.map(e => folderParts(e).length)) : 0;
  const levelHeads = Array.from({ length: levels }, (_, i) =>
    `<th t-group="active:${i}">${i ? 'Unterordner' : 'Ordner'}</th>`).join('');
  const levelCells = e => {
    const parts = folderParts(e);
    return Array.from({ length: levels }, (_, i) => `<td>${esc(parts[i] ?? '')}</td>`).join('');
  };

  return `
    <div class="table-scroll">
      <table class="entry-table" data-variant="${variant}" ${search ? 't-search' : ''}
             ${folders ? 'data-folders t-group-empty="inline"' : ''}>
        <thead><tr>${headerHtml(cols, sortable, variant === 'full')}${levelHeads}</tr></thead>
        <tbody>${list.map(e => entryRowHtml(e, cols, { iconsOn, drag: variant === 'full' })
          .replace(/<\/tr>$/, `${levels ? levelCells(e) : ''}</tr>`)).join('')}</tbody>
      </table>
    </div>`;
}

export function renderEntryTable(host, list, options = {}) {
  if (!list.length) {
    host.innerHTML = `<p class="empty-state">Keine Einträge.</p>`;
    return;
  }
  host.innerHTML = tableHtml(list, options);
  wireEntryRows(host, { select: (options.variant ?? 'full') === 'full' });
  if (options.sortable) ensureTableview();
  tickTotp();
}

/* ---------- Ordner als Gruppen ----------
   Eine Tabelle mit einer Kopfzeile für alles. Der Ordnerpfad steht in
   versteckten Spalten, eine je Ebene, und tableview gruppiert fest danach.
   Mit t-group-empty="inline" stehen die Einträge eines Ordners direkt
   darin, hinter seinen Unterordnern — nicht in einer Gruppe „—". */

/** Trenner in den Gruppenpfaden von tableview ("0:Bank\x1f1:Konten"). */
const GROUP_SEP = '\x1f';

function folderParts(e) {
  return String(e.folder || 'Allgemein').split('/').map(p => p.trim()).filter(Boolean);
}

/**
 * Gruppenpfad von tableview → Ordnerpfad ("Bank/Konten"). Glieder ab
 * `stopCol` gehören nicht zum Ordner (in der Dateiansicht der Eintrag).
 */
function folderOfGroupPath(path, stopCol = Infinity) {
  return String(path).split(GROUP_SEP)
    .filter(seg => Number(seg.slice(0, seg.indexOf(':'))) < stopCol)
    .map(seg => seg.slice(seg.indexOf(':') + 1)).join('/');
}

/** Spalte der Eintragsgruppe in der Dateiansicht, sonst keine. */
const entryColOf = table => Number(table?.dataset.entryCol ?? Infinity);

/** Ordnerpfad → Gruppenpfad; `first` ist die Spalte der obersten Ebene. */
function groupPathOfFolder(folder, first) {
  return folder.split('/').map((part, i) => `${first + i}:${part}`).join(GROUP_SEP);
}

/**
 * Macht die Gruppenzeilen zu Ordnern: Symbol, Ziehen und Ablegen.
 * tableview baut sie bei jedem Sortieren und Aufklappen neu — deshalb
 * nach jedem Durchlauf (Ereignis tableview:groups-rendered).
 */
function decorateFolderRows(table) {
  if (!table?.hasAttribute('data-folders')) return;
  const entryCol = entryColOf(table);
  table.querySelectorAll('tr.tv-group-row').forEach(tr => {
    // Eintragsgruppen der Dateiansicht übernimmt decorateFileGroups.
    if (Number(tr.querySelector('.tv-group-actions')?.dataset.col) === entryCol) return;
    const folder = folderOfGroupPath(tr.dataset.groupPath, entryCol);
    const content = tr.querySelector('.tv-group-content');
    tr.dataset.folder = folder;
    if (!content) return;
    content.dataset.dragId = `folder:${folder}`;
    content.dataset.dragLabel = folder.split('/').pop();
    content.dataset.dropPath = folder;
    const trail = content.querySelector('.tv-group-trail');
    if (trail && !trail.querySelector('.folder-icon')) {
      trail.insertAdjacentHTML('afterbegin', '<span class="msr folder-icon">folder</span>');
    }
  });
}

/** Einmal je Container: Ordnerzeilen bedienen und Aufgeklapptes merken. */
function wireFolderGroups(host) {
  if (host.dataset.foldersWired) return;
  host.dataset.foldersWired = '1';

  host.addEventListener('tableview:groups-rendered', ev => decorateFolderRows(ev.detail.table));

  // Doppelklick öffnet den Ordner-Dialog; das doppelte Umschalten durch
  // die beiden Klicks hebt sich auf.
  host.addEventListener('dblclick', ev => {
    const tr = ev.target.closest('tr.tv-group-row[data-folder]');
    if (!tr) return;
    ev.preventDefault();
    openFolderDialog({ path: tr.dataset.folder });
  });

  host.addEventListener('contextmenu', ev => {
    const tr = ev.target.closest('tr.tv-group-row[data-folder]');
    if (!tr) return;
    ev.preventDefault();
    ev.stopPropagation();
    showContextMenu(ev.clientX, ev.clientY, { folderPath: tr.dataset.folder });
  });

  // tableview führt die offenen Gruppen in t-open. Jede Änderung dort
  // wandert als Ordnerpfad in die Einstellungen.
  new MutationObserver(records => {
    const table = records.map(r => r.target).find(t => t.hasAttribute?.('data-folders'));
    if (!table) return;
    let paths;
    try { paths = JSON.parse(table.getAttribute('t-open') || '[]'); } catch { return; }
    if (!Array.isArray(paths)) return;
    // Aufgeklappte Eintragsgruppen der Dateiansicht zählen nicht als Ordner.
    const next = new Set(paths.map(p => folderOfGroupPath(p, entryColOf(table))).filter(Boolean));
    if (next.size === state.expanded.size && [...next].every(p => state.expanded.has(p))) return;
    state.expanded = next;
    persistExpanded();
  }).observe(host, { subtree: true, attributes: true, attributeFilter: ['t-open'] });
}

export function renderPasswords() {
  renderLegend();
  const host = $('#entry-table');
  const list = visibleEntries();

  if (state.kindFilter === 'files') { renderFiles(host, list); return; }

  if (!list.length) {
    host.innerHTML = `<p class="empty-state">Keine Einträge gefunden.</p>`;
    return;
  }

  // Bei aktiver Suche fallen die Ordner weg — eine flache Liste über alles.
  if (state.search) {
    host.innerHTML = tableHtml(list, { variant: 'full', sortable: true });
    wireEntryRows(host);
    ensureTableview();
    return;
  }

  // Ohne t-search: Die Suche oben in der App gilt für alles.
  host.innerHTML = tableHtml(list, { sortable: true, folders: true });

  // Offene Ordner vorgeben, bevor tableview die Tabelle zum ersten Mal
  // zeichnet (das passiert erst nach diesem Durchlauf).
  const table = host.querySelector('table');
  const first = COLUMNS.full.length + (pick.selectionActive() ? 1 : 0);
  table.setAttribute('t-open', JSON.stringify([...state.expanded].map(f => groupPathOfFolder(f, first))));

  wireFolderGroups(host);
  wireEntryRows(host);
  setupDragMove(host);
  ensureTableview();
}

/* ---------- Dateien ----------
   Jede Datei eine Zeile, in derselben Ordnerstruktur wie die Einträge.
   Ein Eintrag mit mehreren Dateien ist darin ein Unterordner; einer mit
   nur einer Datei bekommt keine eigene Gruppe, seine Datei steht direkt im
   Ordner (t-group-empty="inline"). Ein Klick auf die Datei zeigt sie
   sofort, ⓘ öffnet den Eintrag mit Name, Passwort und Notizen. */

/** Sichtbare Spalten vor den Gruppenspalten: Symbol, Datei, Knöpfe. */
const FILE_COLS = 3;

/** Gruppenname → Eintrag, für den ⓘ-Knopf an den Eintragsgruppen. */
let fileGroups = new Map();

const infoButton = id => `<button type="button" class="button" data-shape="square" data-file-info="${id}"
  title="Eintrag öffnen — Name, Passwort, Notizen" aria-label="Eintrag öffnen"><span class="msr">info</span></button>`;

export function renderFiles(host, list) {
  const entries = list.filter(hasFiles);
  if (!entries.length) {
    host.innerHTML = `<p class="empty-state">Keine Dateien gefunden.</p>`;
    return;
  }

  // Gleichnamige Einträge dürfen nicht in eine Gruppe zusammenfallen.
  const names = new Map();
  for (const e of entries) names.set(e.name, (names.get(e.name) ?? 0) + 1);
  const groupName = e => names.get(e.name) > 1 ? `${e.name} (${e.folder || 'Allgemein'})` : e.name;

  const levels = Math.max(1, ...entries.map(e => folderParts(e).length));
  const entryCol = FILE_COLS + levels;

  fileGroups = new Map();
  const rows = entries.flatMap(e => {
    const single = e.attachments.length === 1;
    const group = single ? '' : groupName(e);
    if (group) fileGroups.set(group, e.id);
    const parts = folderParts(e);
    const levelCells = Array.from({ length: levels }, (_, i) => `<td>${esc(parts[i] ?? '')}</td>`).join('');

    return e.attachments.map(att => `
      <tr data-file-entry="${e.id}" data-file-name="${esc(att.name)}" title="${esc(att.name)} — zum Anzeigen klicken">
        <td data-col="avatar"><span class="msr file-icon">${preview.iconFor({ name: att.name, type: preview.typeFromName(att.name) })}</span></td>
        <td data-col="name"><span class="cell-name">${esc(att.name)}</span>${
          single ? `<small class="file-entry">${esc(e.name)}</small>` : ''}</td>
        <td data-col="actions"><div class="row-actions">
          ${single ? infoButton(e.id) : ''}
          <button type="button" class="button" data-shape="square" data-file-save title="Herunterladen" aria-label="Herunterladen"><span class="msr">download</span></button>
        </div></td>
        ${levelCells}
        <td>${esc(group)}</td>
      </tr>`);
  });

  host.innerHTML = `
    <div class="table-scroll">
      <table class="entry-table file-table" data-files data-folders data-entry-col="${entryCol}" t-group-empty="inline">
        <thead><tr>
          <th data-col="avatar"></th><th data-col="name" t-sort="asc">Datei</th><th data-col="actions"></th>
          ${Array.from({ length: levels }, (_, i) => `<th t-group="active:${i}">${i ? 'Unterordner' : 'Ordner'}</th>`).join('')}
          <th t-group="active:${levels}">Eintrag</th>
        </tr></thead>
        <tbody>${rows.join('')}</tbody>
      </table>
    </div>`;

  // Dieselben Ordner offen wie unter „Einträge".
  host.querySelector('table').setAttribute('t-open',
    JSON.stringify([...state.expanded].map(f => groupPathOfFolder(f, FILE_COLS))));

  wireFolderGroups(host);
  wireFiles(host);
  ensureTableview();
}

/** Eintragsgruppen bekommen ihren ⓘ-Knopf; nach jedem Zeichnen neu. */
function decorateFileGroups(table) {
  if (!table?.hasAttribute('data-files')) return;
  const entryCol = entryColOf(table);
  table.querySelectorAll('tr.tv-group-row').forEach(tr => {
    const box = tr.querySelector('.tv-group-actions');
    if (Number(box?.dataset.col) !== entryCol) return;
    const trail = tr.querySelector('.tv-group-trail');
    if (trail && !trail.querySelector('.file-icon')) {
      trail.insertAdjacentHTML('afterbegin', '<span class="msr file-icon">folder_zip</span>');
    }
    if (box.childElementCount) return;
    const key = tr.dataset.groupPath.split(GROUP_SEP).pop();
    const id = fileGroups.get(key.slice(key.indexOf(':') + 1));
    if (id) box.innerHTML = infoButton(id);
  });
}

/** Einmal je Container: Klicks auf Dateien, ⓘ und Herunterladen. */
function wireFiles(host) {
  if (host.dataset.filesWired) return;
  host.dataset.filesWired = '1';

  host.addEventListener('tableview:groups-rendered', ev => decorateFileGroups(ev.detail.table));

  // In der Einfangphase: Der ⓘ in einer Gruppenzeile soll die Gruppe
  // nicht zugleich auf- oder zuklappen.
  host.addEventListener('click', ev => {
    if (!ev.target.closest('table[data-files]')) return;
    const info = ev.target.closest('[data-file-info]');
    const save = ev.target.closest('[data-file-save]');
    if (!info && !save) return;
    ev.stopPropagation();
    ev.preventDefault();
    if (info) { openEntryDialog(info.dataset.fileInfo); return; }
    const row = save.closest('tr[data-file-entry]');
    if (row) saveStoredFile(row.dataset.fileEntry, row.dataset.fileName);
  }, true);

  host.addEventListener('click', ev => {
    const row = ev.target.closest('table[data-files] tr[data-file-entry]');
    if (row) openStoredFile(row.dataset.fileEntry, row.dataset.fileName);
  });
}

export async function storedFiles(entryId) {
  const entry = byId(entryId);
  return entry ? loadAttachments(entry) : [];
}

async function saveStoredFile(entryId, name) {
  const att = (await storedFiles(entryId)).find(a => a.name === name);
  if (att) downloadWithWarning(att);
  else banner('Die Datei ließ sich nicht lesen.', 'error');
}

/**
 * Zeigt eine Datei, ohne erst den Eintrag zu öffnen. Die Vorschau arbeitet
 * auf dem „offenen Eintrag" (Umbenennen und Bearbeiten schreiben dorthin) —
 * für ihre Dauer ist das dieser hier.
 */
export async function openStoredFile(entryId, name) {
  const files = await storedFiles(entryId);
  const att = files.find(a => a.name === name);
  if (!att) { banner('Die Datei ließ sich nicht lesen.', 'error'); return; }

  const before = files.map(a => `${a.name}\n${a.ref}`).join('\n');
  state.dialogEntryId = entryId;
  state.dialogAttachments = files;

  // Die Vorschau kehrt erst zurück, wenn sie zu ist — danach aufräumen.
  await openAttachmentViewer(att);
  state.dialogEntryId = null;
  state.dialogAttachments = [];
  // Umbenannt oder bearbeitet: Liste neu, damit Name und Inhalt stimmen.
  if (files.map(a => `${a.name}\n${a.ref}`).join('\n') !== before) {
    await refreshFromVault();
    renderPasswords();
  }
}

/** Rüstet die eben gebauten Tabellen mit Sortierung aus. */
export function ensureTableview() {
  return tableview();
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

export function setupDragMove(host) {
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

    return nachStrukturaenderung(moving.length === 1
      ? `Nach „${targetPath}“ verschoben.`
      : `${moving.length} Einträge nach „${targetPath}“ verschoben.`);
  }

  const from = dragId.slice(7);
  if (from === targetPath) return;

  const ok = await vault.moveFolder(from, targetPath);
  if (!ok) return banner('Dieser Ordner lässt sich dorthin nicht verschieben.', 'warning');
  return nachStrukturaenderung('Ordner verschoben.');
}

async function placeNextTo(dragId, refId, position) {
  if (!refId || dragId === refId) return;

  if (dragId.startsWith('entry:') && refId.startsWith('entry:')) {
    const ok = await vault.reorderEntry(dragId.slice(6), refId.slice(6), position);
    if (!ok) return;
    return nachStrukturaenderung('Reihenfolge geändert.');
  }

  if (dragId.startsWith('folder:') && refId.startsWith('folder:')) {
    const ok = await vault.reorderFolder(dragId.slice(7), refId.slice(7), position);
    if (!ok) return banner('Dieser Ordner lässt sich dorthin nicht verschieben.', 'warning');
    return nachStrukturaenderung('Reihenfolge geändert.');
  }

  // Eintrag neben einem Ordner: in dessen Elternordner einordnen
  if (dragId.startsWith('entry:') && refId.startsWith('folder:')) {
    const parent = refId.slice(7).split('/').slice(0, -1).join('');
    return moveInto(dragId, parent);
  }
}


/* =========================================================
   Anlegen — Auswahl zwischen Formular und Kamera
   ========================================================= */

/**
 * Leiste am unteren Rand, solange etwas ausgewählt ist.
 *
 * Sie zeigt, wie viele es sind, und bietet den Weg heraus — sonst käme man
 * auf dem Handy aus dem Auswahlmodus nicht mehr zurück.
 */
export function renderSelectionBar() {
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
  renderAll({ ohne: ['einstellungen'] });
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
  renderAll({ ohne: ['einstellungen'] });
  banner(`${ids.length} ${ids.length === 1 ? 'Eintrag' : 'Einträge'} gelöscht.`, 'success');
}


/* =========================================================
   Sperren und Entsperren
   ========================================================= */
