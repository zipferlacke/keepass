/**
 * konflikte.js — „Hier so, in der Datei anders: welche Fassung?"
 *
 * Beim Zusammenführen gilt die jüngere Fassung eines Eintrags. Wurde ein
 * Eintrag auf beiden Seiten seit dem letzten gemeinsamen Stand verschieden
 * geändert, entscheidet der Nutzer: Der Dialog zeigt je Eintrag die
 * Änderungen hier und in der Datei sowie die gerade geltende Fassung. Die Konflikte selbst führt der Kern (konflikt.rs).
 */

import * as vault from '../data/vault.js';
import { dialog, banner } from '../ui/libs.js';
import { esc } from '../core/state.js';
import { t } from '../core/i18n.js';
import { renderAll, refreshFromVault } from '../core/render.js';

/** Verhindert, dass der Dialog zweimal geöffnet wird. */
let offen = false;

/** Die Änderungen einer Seite — Passwörter ohne Wert, wie bei den Versionen. */
function seite(titel, art, felder) {
  if (art === 'geloescht') return `<div class="konflikt-seite"><strong>${titel}</strong><p>${t('dialoge.konflikte.seite.geloescht')}</p></div>`;
  const zeilen = felder.map(f => f.before == null && f.after == null
    ? `<li>${t('dialoge.konflikte.seite.feldGeaendert', { name: esc(f.name) })}</li>`
    : `<li>${esc(f.name)}: <del>${esc(f.before || '—')}</del> <span class="msr">arrow_forward</span> ${esc(f.after || '—')}</li>`).join('');
  return `<div class="konflikt-seite"><strong>${titel}</strong><ul>${zeilen || `<li>${art === 'geaendert' ? t('dialoge.konflikte.art.geaendert') : art === 'geloescht' ? t('dialoge.konflikte.art.geloescht') : art}</li>`}</ul></div>`;
}

function karte(k) {
  const gilt = k.winner === 'hier' ? t('dialoge.konflikte.gilt.hier') : t('dialoge.konflikte.gilt.datei');
  return `
    <div class="konflikt" data-konflikt="${esc(k.id)}">
      <div class="konflikt-kopf">
        <span class="msr">call_split</span>
        <strong>${esc(k.name || t('dialoge.konflikte.ohneTitel'))}</strong>
        ${k.folder ? `<small>${esc(k.folder)}</small>` : ''}
      </div>
      <div class="konflikt-seiten">
        ${seite(t('dialoge.konflikte.seite.hier'), k.hereKind, k.here)}
        ${seite(t('dialoge.konflikte.seite.datei'), k.fileKind, k.file)}
      </div>
      <small class="konflikt-gilt">${gilt}</small>
      <div class="konflikt-wahl">
        <button type="button" class="button ${k.winner === 'hier' ? 'hightlight' : ''}" data-wahl="hier">${t('dialoge.konflikte.wahl.behalten')}</button>
        <button type="button" class="button ${k.winner === 'extern' ? 'hightlight' : ''}" data-wahl="extern">${t('dialoge.konflikte.wahl.nehmen')}</button>
      </div>
    </div>`;
}

/** Zeigt die offenen Konflikte; ohne Konflikte geschieht nichts. */
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
      title: liste.length === 1 ? t('dialoge.konflikte.titel.eins') : t('dialoge.konflikte.titel.mehrere', { n: liste.length }),
      content: `
        <p class="dlg-note">${t('dialoge.konflikte.hinweis')}</p>
        <div class="konflikte">${liste.map(karte).join('')}</div>`,
      confirmText: null,
      cancelText: t('dialoge.konflikte.spaeter'),
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
              ? t('dialoge.konflikte.entschieden.hier') : t('dialoge.konflikte.entschieden.datei');
          } catch (err) {
            box.querySelectorAll('button').forEach(b => { b.disabled = false; });
            banner(t('dialoge.konflikte.fehler', { fehler: err.message }), 'error', 6000);
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
