/**
 * icons.js — Website-Icons für Einträge.
 *
 * Die Oberfläche lädt nichts aus dem Netz. Der Kern holt das Icon einmal
 * von der Seite (favicon.rs) und speichert es als Custom Icon verschlüsselt
 * in der Datenbank. Hier kommt es als `entry.icon` (`data:`-Adresse) an.
 */

export function hostFromUrl(url) {
  if (!url) return null;
  try {
    const withScheme = /^https?:\/\//i.test(url) ? url : `https://${url}`;
    const host = new URL(withScheme).hostname;
    return host && host.includes('.') ? host : null;
  } catch { return null; }
}

/**
 * Markup für das Symbol eines Eintrags: das gespeicherte Icon, sonst der
 * Anfangsbuchstabe. `enabled: false` zeigt immer den Buchstaben.
 */
export function avatarMarkup(entry, { enabled = true } = {}) {
  const letter = (entry.name ?? '?').trim()[0]?.toUpperCase() ?? '?';
  const icon = enabled && typeof entry.icon === 'string' && entry.icon.startsWith('data:image/') ? entry.icon : null;

  if (!icon) return `<span class="entry-avatar">${letter}</span>`;

  return `<span class="entry-avatar" data-has-icon>
    <span class="avatar-letter">${letter}</span>
    <img class="avatar-img" src="${icon}" alt="" onerror="this.closest('.entry-avatar').removeAttribute('data-has-icon'); this.remove()">
  </span>`;
}
