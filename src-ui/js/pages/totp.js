/**
 * totp.js — die Seite mit den Einmalcodes.
 *
 * Jede Karte zeigt den laufenden Code, den Ring mit der Restzeit und —
 * in den letzten Sekunden — klein darunter den, der als Nächstes gilt.
 * Gerechnet wird im Kern; hier wird nur jede Sekunde nachgefragt.
 */

import * as vault from '../data/vault.js';
import { state, $, $$, esc } from '../core/state.js';
import { copyPlain } from '../ui/clipboard.js';
import { avatarMarkup } from '../core/icons.js';
import { markUsed } from '../core/entries.js';
import { openEntryDialog } from '../dialogs/entry.js';

/* ---------- TOTP ---------- */
export const PREVIEW_SECONDS = 10;   // ab hier den kommenden Code klein einblenden

export function renderTotp() {
  const list = state.entries.filter(e => e.hasTotp);
  const host = $('#totp-list');

  if (!list.length) {
    host.innerHTML = `<p class="empty-state">Keine TOTP-Einträge vorhanden.</p>`;
    return;
  }

  host.innerHTML = list.map(e => `
    <div class="totp-card" data-totp-card="${e.id}" title="Klick kopiert, Doppelklick öffnet den Eintrag">
      <div class="totp-ring">
        <svg viewBox="0 0 36 36">
          <circle class="track" cx="18" cy="18" r="15"></circle>
          <circle class="progress" cx="18" cy="18" r="15" data-ring="${e.id}"></circle>
        </svg>
        <span class="totp-seconds" data-sec="${e.id}"></span>
      </div>
      <div class="totp-body">
        <div class="totp-name">${esc(e.name)}</div>
        <div class="totp-issuer">${esc(e.url || e.username || '—')}</div>
      </div>
      <div class="totp-values">
        <div class="totp-value" data-code="${e.id}">······</div>
        <div class="totp-next" data-next="${e.id}" hidden></div>
      </div>
    </div>`).join('');

  // Einfacher Klick kopiert, Doppelklick öffnet — der Einzelklick wartet
  // kurz ab, damit er einen Doppelklick nicht vorwegnimmt.
  host.querySelectorAll('[data-totp-card]').forEach(card => {
    let timer = null;

    card.addEventListener('click', () => {
      if (timer) return;
      timer = setTimeout(() => {
        timer = null;
        const code = state.codes.get(card.dataset.totpCard)?.code;
        if (code) markUsed(card.dataset.totpCard);
        if (code) copyPlain(code, 'Code kopiert');
      }, 220);
    });

    card.addEventListener('dblclick', () => {
      clearTimeout(timer);
      timer = null;
      openEntryDialog(card.dataset.totpCard);
    });
  });

  tickTotp();
}

let ticking = false;

export async function tickTotp() {
  if (ticking || state.locked) return;
  ticking = true;
  try { await tickTotpInner(); } finally { ticking = false; }
}

async function tickTotpInner() {
  const circ = 2 * Math.PI * 15;

  for (const e of state.entries) {
    if (!e.hasTotp) continue;

    const result = await vault.totpFor(e);
    if (!result) continue;

    state.codes.set(e.id, result);

    const period = e.totpConfig?.period || 30;
    $$(`[data-code="${e.id}"]`).forEach(el => el.textContent = result.code);
    $$(`[data-totp="${e.id}"]`).forEach(el => el.textContent = result.code);
    $$(`[data-sec="${e.id}"]`).forEach(el => el.textContent = result.remaining);
    $$(`[data-ring="${e.id}"]`).forEach(el => {
      el.setAttribute('stroke-dasharray', circ);
      el.setAttribute('stroke-dashoffset', circ * (1 - result.remaining / period));
      el.classList.toggle('ending', result.remaining <= PREVIEW_SECONDS);
    });

    // Kurz vor Ablauf schon den nächsten Code zeigen
    const nextNodes = $$(`[data-next="${e.id}"]`);
    if (nextNodes.length) {
      if (result.remaining <= PREVIEW_SECONDS) {
        const upcoming = await vault.totpFor(e, { at: Date.now() + (result.remaining + 1) * 1000 });
        nextNodes.forEach(el => {
          el.textContent = `als Nächstes ${upcoming?.code ?? '······'}`;
          el.hidden = false;
        });
      } else {
        nextNodes.forEach(el => { el.hidden = true; });
      }
    }
  }
}
