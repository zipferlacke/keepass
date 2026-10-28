/**
 * konflikte.js — „Hier so, in der Datei anders: welche Fassung?"
 *
 * Beim Zusammenführen gilt die jüngere Fassung eines Eintrags. Haben aber
 * beide Seiten denselben Eintrag seit dem letzten gemeinsamen Stand
 * verschieden geändert, soll der Nutzer entscheiden — dieser Dialog zeigt
 * je Eintrag, was hier und was in der Datei geändert wurde, und welche
 * Fassung gerade gilt. Die Konflikte selbst führt der Kern (konflikt.rs).
 */

import * as vault from '../data/vault.js';
import { dialog, banner } from '../ui/libs.js';
import { esc } from '../core/state.js';
import { renderAll, refreshFromVault } from '../core/render.js';

/** Steht der Dialog schon? Dann nicht ein zweites Mal öffnen. */
let offen = false;

const ART = { geaendert: 'geändert', geloescht: 'gelöscht' };

/** Die Änderungen einer Seite — Passwörter ohne Wert, wie bei den Versionen. */
function seite(titel, art, felder) {
  if (art === 'geloescht') return `<div class="konflikt-seite"><strong>${titel}</strong><p>Eintrag gelöscht</p></div>`;
  const zeilen = felder.map(f => f.before == null && f.after == null
    ? `<li>${esc(f.name)} geändert</li>`
    : `<li>${esc(f.name)}: <del>${esc(f.before || '—')}</del> <span class="msr">arrow_forward</span> ${esc(f.after || '—')}</li>`).join('');
  return `<div class="konflikt-seite"><strong>${titel}</strong><ul>${zeilen || `<li>${ART[art] ?? art}</li>`}</ul></div>`;
}

function karte(k) {
  const gilt = k.winner === 'hier' ? 'Gerade gilt die Fassung von hier.' : 'Gerade gilt die Fassung aus der Datei.';
  return `
    <div class="konflikt" data-konflikt="${esc(k.id)}">
      <div class="konflikt-kopf">
        <span class="msr">call_split</span>
        <strong>${esc(k.name || '(ohne Titel)')}</strong>
        ${k.folder ? `<small>${esc(k.folder)}</small>` : ''}
      </div>
      <div class="konflikt-seiten">
        ${seite('Hier geändert', k.hereKind, k.here)}
        ${seite('In der Datei geändert', k.fileKind, k.file)}
      </div>
      <small class="konflikt-gilt">${gilt}</small>
      <div class="konflikt-wahl">
        <button type="button" class="button ${k.winner === 'hier' ? 'hightlight' : ''}" data-wahl="hier">Meine behalten</button>
        <button type="button" class="button ${k.winner === 'extern' ? 'hightlight' : ''}" data-wahl="extern">Aus der Datei nehmen</button>
      </div>
    </div>`;
}

/**
 * Zeigt die offenen Konflikte. Gibt es keine, passiert nichts — darf also
 * jederzeit aufgerufen werden (nach dem Entsperren, nach einem Abgleich).
 */
export async function openKonflikte() {
  if (offen) return;
  let liste;
  try {
    liste = await vault.conflicts();
  } catch {
    return;
  }
  if (!liste?.length) return;

  offen = true;
  let entschieden = 0;
  try {
    await dialog({
      title: liste.length === 1 ? 'Ein Eintrag wurde auf beiden Seiten geändert' : `${liste.length} Einträge wurden auf beiden Seiten geändert`,
      content: `
        <p class="dlg-note">Seit dem letzten Abgleich wurden diese Einträge hier und in der Datei
        verschieden geändert. Welche Fassung soll gelten? Bis du entscheidest, gilt die jüngere.</p>
        <div class="konflikte">${liste.map(karte).join('')}</div>`,
      confirmText: null,
      cancelText: 'Später',
      onInsert: id => {
        const host = document.getElementById(String(id));
        host?.querySelectorAll('[data-wahl]').forEach(btn => btn.addEventListener('click', async () => {
          const box = btn.closest('[data-konflikt]');
          box.querySelectorAll('button').forEach(b => { b.disabled = true; });
          try {
            await vault.resolveConflict(box.dataset.konflikt, btn.dataset.wahl);
            await vault.commit();
            entschieden++;
            box.classList.add('entschieden');
            box.querySelector('.konflikt-gilt').textContent = btn.dataset.wahl === 'hier'
              ? 'Entschieden: deine Fassung.' : 'Entschieden: die Fassung aus der Datei.';
          } catch (err) {
            box.querySelectorAll('button').forEach(b => { b.disabled = false; });
            banner(`Nicht übernommen: ${err.message}`, 'error', 6000);
          }
        }));
      }
    });
  } finally {
    offen = false;
  }

  if (entschieden) {
    await refreshFromVault();
    renderAll({ ohne: ['einstellungen'] });
  }
}
