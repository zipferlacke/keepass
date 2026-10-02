/**
 * icons.js — Website-Icons für Einträge.
 *
 * Die Oberfläche lädt selbst nichts aus dem Netz. Das Icon holt der Kern
 * einmal von der Seite (favicon.rs) und legt es als Custom Icon in die
 * Datenbank — verschlüsselt, offline verfügbar und auf jedem Gerät, das die
 * Datei öffnet. Hier kommt es als `entry.icon` (`data:`-Adresse) an.
 *
 * Früher lud jede Anzeige das Icon direkt von der Seite. Das ging bei allem
 * schief, was nur in einem bestimmten Netz erreichbar ist, und jede
 * Anzeige verriet der Seite die eigene Adresse.
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
