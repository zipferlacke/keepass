/**
 * folder.js — Ordner anlegen und bearbeiten.
 *
 * Ein Ordner ist in der Datei eine Gruppe; hier ist er ein Pfad mit
 * Schrägstrichen. Umbenennen und Verschieben sind zwei Schritte im Kern,
 * im Dialog ist es einer.
 */

import * as vault from '../data/vault.js';
import { dialog, banner, zurueckZu } from '../ui/libs.js';
import { esc } from '../core/state.js';
import { nachStrukturaenderung, refreshFromVault, renderAll } from '../core/render.js';

export async function openFolderDialog({ parent = '', path = null, zurueck = null } = {}) {
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
          <select id="fld-folder-parent" name="parent" data-sp-picker>
            ${options.map(f => `<option value="${esc(f)}" ${f === parentPath ? 'selected' : ''}>${f ? esc(f) : '— oberste Ebene —'}</option>`).join('')}
          </select>
        </div>
      </div>`,
    confirmText: isEdit ? 'Speichern' : 'Anlegen',
    cancelText: 'Abbrechen',
    onBack: zurueckZu(zurueck)
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
  renderAll({ ohne: ['einstellungen'] });
  banner(isEdit ? 'Ordner gespeichert.' : 'Ordner angelegt.', 'success');
}
