/**
 * attachments.js — Anhänge zwischen Kern und Oberfläche.
 *
 * In der Datenbank liegen Dateien verschlüsselt; hierher kommen sie als
 * Data-URL, zusammen mit Name, Art und Größe. Das Herunterladen gibt es
 * nur mit Warnung: Auf der Platte ist die Datei nicht mehr verschlüsselt.
 */

import * as vault from '../data/vault.js';
import { dialog, banner } from '../ui/libs.js';
import { pickSavePath } from '../core/platform.js';
import { esc } from '../core/state.js';

/* =========================================================
   Anhänge laden
   ========================================================= */
export async function loadAttachments(entry) {
  const out = [];
  for (const att of entry.attachments ?? []) {
    if (att.ref === null || att.ref === undefined) continue;
    const stored = await vault.attachmentData(att.ref);
    if (stored) out.push({ name: att.name, type: stored.type, size: sizeOfDataUrl(stored.data), data: stored.data, ref: att.ref });
  }
  return out;
}

export function sizeOfDataUrl(dataUrl) {
  const b64 = String(dataUrl).split(',')[1] ?? '';
  return Math.floor(b64.length * 3 / 4);
}

export function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 ** 2).toFixed(1)} MB`;
}

/**
 * Herunterladen — erst nach ausdrücklicher Warnung.
 *
 * In der Datenbank ist die Datei verschlüsselt. Auf der Platte ist sie das
 * nicht mehr, und das soll niemand nebenbei übersehen.
 */
export async function downloadWithWarning(att) {
  if (!att) return;

  const res = await dialog({
    title: 'Unverschlüsselt speichern?',
    type: 'warning',
    content: `<p>„${esc(att.name)}“ liegt in der Datenbank verschlüsselt. Beim Herunterladen
      wird die Datei <strong>unverschlüsselt</strong> auf die Festplatte geschrieben.</p>
      <p>Danach kann sie jedes Programm und jeder mit Zugriff auf diesen Ordner lesen, und eine
      Synchronisierung nimmt sie womöglich mit. Lösche die Kopie, wenn du sie nicht mehr brauchst.</p>`,
    confirmText: 'Unverschlüsselt speichern',
    cancelText: 'Abbrechen'
  });

  if (!(res?.submit ?? res)) return;
  await saveAttachment(att);
}

/**
 * Schreibt einen Anhang als Datei — über den Kern, nicht über den Webview.
 *
 * Ein `<a download>` bewirkt hier nichts: WebKitGTK bringt in einem
 * eingebetteten View keine Download-Behandlung mit, der Klick verpufft
 * folgenlos. Deshalb fragt der Kern nach dem Ort und schreibt selbst.
 */
export async function saveAttachment(att) {
  try {
    const path = await vault.saveAttachment(att.ref);
    if (path) banner(`Gespeichert unter ${path}`, 'success', 5000);
  } catch (err) {
    banner(`Speichern fehlgeschlagen: ${err.message}`, 'error', 6000);
  }
}

export function generatePassword(length = 20) {
  const pool = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*+-=?';
  const bytes = crypto.getRandomValues(new Uint32Array(length));
  return [...bytes].map(b => pool[b % pool.length]).join('');
}
