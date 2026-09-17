/**
 * icons.js — Website-Icons für Einträge.
 *
 * Datenschutz: geladen wird ausschließlich direkt von der jeweiligen
 * Zieldomain. Es ist bewusst kein Sammeldienst eingebunden — der würde
 * sonst die vollständige Liste deiner Konten mitlesen können. Die
 * Zieldomain selbst sieht beim Laden deine IP-Adresse; wem auch das zu
 * viel ist, schaltet die Option in den Einstellungen ab.
 *
 * Nicht jede Seite legt ihr Icon unter /favicon.ico ab — verbreitet sind
 * inzwischen auch .svg und .png. Deshalb werden mehrere Kandidaten der
 * Reihe nach probiert, bis einer lädt.
 */

const CANDIDATES = [
  '/favicon.ico',
  '/favicon.svg',
  '/favicon.png',
  '/apple-touch-icon.png',
  '/apple-touch-icon-precomposed.png'
];

/** Wird hochgezählt, wenn der Nutzer „Icons neu laden" auslöst. */
let epoch = 0;
export function refreshEpoch() { epoch++; return epoch; }
export function currentEpoch() { return epoch; }

export function hostFromUrl(url) {
  if (!url) return null;
  try {
    const withScheme = /^https?:\/\//i.test(url) ? url : `https://${url}`;
    const host = new URL(withScheme).hostname;
    return host && host.includes('.') ? host : null;
  } catch { return null; }
}

export function iconCandidates(url) {
  const host = hostFromUrl(url);
  if (!host) return [];
  const bust = epoch ? `?r=${epoch}` : '';
  return CANDIDATES.map(path => `https://${host}${path}${bust}`);
}

/**
 * Markup für das Symbol eines Eintrags.
 * Schlägt ein Kandidat fehl, rückt der onerror-Handler zum nächsten weiter;
 * ist die Liste erschöpft, bleibt der Buchstabe stehen.
 */
export function avatarMarkup(entry, { enabled = true } = {}) {
  const letter = (entry.name ?? '?').trim()[0]?.toUpperCase() ?? '?';
  const list = enabled ? iconCandidates(entry.url) : [];

  if (!list.length) return `<span class="entry-avatar">${letter}</span>`;

  const remaining = list.slice(1).join('|');

  return `<span class="entry-avatar" data-has-icon>
    <span class="avatar-letter">${letter}</span>
    <img class="avatar-img" src="${list[0]}" alt="" loading="lazy" referrerpolicy="no-referrer"
         data-fallbacks="${remaining}"
         onerror="(function(i){
           const rest=(i.dataset.fallbacks||'').split('|').filter(Boolean);
           if(rest.length){ i.src=rest.shift(); i.dataset.fallbacks=rest.join('|'); }
           else { i.closest('.entry-avatar').removeAttribute('data-has-icon'); i.remove(); }
         })(this)">
  </span>`;
}
