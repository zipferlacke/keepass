/**
 * entries.js — die kleinen Auskünfte über Einträge.
 *
 * Was zählt als Datei, was ist abgelaufen, was ist im Papierkorb, wann
 * wurde ein Eintrag zuletzt benutzt: Fragen, die auf jeder Seite
 * auftauchen und nirgendwo hingehören — also hierher.
 *
 * Geschrieben wird hier nur eines: `markUsed` merkt sich im Kern, dass ein
 * Eintrag benutzt wurde. Alles andere liest nur.
 */

import * as vault from '../data/vault.js';
import * as settings from '../data/settings.js';
import { state } from './state.js';
import { zeichne } from './render.js';

/**
 * Einträge ohne den Papierkorb.
 *
 * Was gelöscht ist, bleibt sichtbar — aber ein schwaches Passwort im
 * Papierkorb ist kein Befund, sondern Altlast. Alle Auswertungen laufen
 * deshalb hierüber.
 */
export function liveEntries() {
  return state.entries.filter(e => !e.recycled);
}

export function visibleEntries() {
  return state.entries.filter(e => {
    if (state.kindFilter === 'passkey' && !e.passkey) return false;
    if (state.kindFilter === 'files' && !hasFiles(e)) return false;
    if (state.tag && !(e.tags ?? []).includes(state.tag)) return false;
    if (state.search) {
      const hay = `${e.name} ${e.username} ${e.url} ${(e.tags ?? []).join(' ')}`.toLowerCase();
      if (!hay.includes(state.search)) return false;
    }
    return true;
  });
}

export function expiryState(entry) {
  if (!entry.expires) return null;
  const days = Math.ceil((new Date(entry.expires).setHours(23, 59, 59) - Date.now()) / 86_400_000);
  if (days < 0) return { kind: 'expired', days };
  const warnDays = settings.forDatabase(settings.get('database.current', null)).expiryWarnDays ?? 14;
  if (days <= warnDays) return { kind: 'expiring', days };
  return null;
}

export function byId(id) { return state.entries.find(e => e.id === id); }

/** Trägt der Eintrag Anhänge? */
export function hasFiles(entry) {
  return !entry.recycled && (entry.attachments ?? []).length > 0;
}

/**
 * Ist das eine reine Dateiablage — nur Name und Anhänge?
 *
 * Solche Einträge öffnen sich als Dateiliste statt als Passwortformular.
 * Notizen und Tags zählen nicht dagegen; sobald Benutzername, URL,
 * Passwort, TOTP oder Passkey dazukommen, ist es ein normaler Eintrag.
 */
export function isFileEntry(entry) {
  return (entry.attachments ?? []).length > 0 &&
    !entry.username && !entry.url && !entry.hasPassword && !entry.hasTotp && !entry.passkey;
}


/** So viele Einträge behalten ihren letzten Zeitpunkt auch ohne Nutzung in der Woche. */
export const USED_LIMIT = 30;

export const USAGE_WINDOW = 7 * 24 * 60 * 60 * 1000;

/** Nutzung der offenen Datenbank: `{ [uuid]: { at, week: [ms…] } }`, bereinigt. */
export function usageMap(now = Date.now()) {
  const stored = settings.forDatabase(settings.get('database.current', null));
  const map = {};

  // Ältere Fassung: nur eine Liste mit dem letzten Zeitpunkt.
  for (const u of stored.usedEntries ?? []) map[u.id] = { at: u.at, week: [u.at] };
  for (const [id, u] of Object.entries(stored.usage ?? {})) map[id] = { at: u.at ?? 0, week: [...(u.week ?? [])] };

  const newest = new Set(Object.entries(map)
    .sort(([, a], [, b]) => b.at - a.at)
    .slice(0, USED_LIMIT)
    .map(([id]) => id));

  for (const [id, u] of Object.entries(map)) {
    u.week = u.week.filter(t => now - t < USAGE_WINDOW);
    if (!u.week.length && !newest.has(id)) delete map[id];
  }
  return map;
}

/** Vermerkt, dass Einträge gerade benutzt wurden — eine UUID oder mehrere. */
export function markUsed(ids) {
  const path = settings.get('database.current', null);
  const list = [ids].flat().filter(Boolean);
  if (!list.length || !path) return;

  // Auch in der Datei (LastAccessTime) — daraus entsteht „Inaktive
  // Einträge", und KeePassXC sieht denselben Zeitpunkt.
  vault.markAccessed(list).catch(() => {});
  // Wer einen Eintrag benutzt, ist meist gerade im passenden Netz.
  vault.fetchIcons(list).catch(() => {});

  const now = Date.now();
  const map = usageMap(now);
  for (const id of list) {
    const u = map[id] ??= { at: 0, week: [] };
    u.at = now;
    u.week.push(now);
  }

  // Still speichern: Die Liste soll kein Neuzeichnen aller Ansichten auslösen.
  settings.setForDatabase(path, 'usage', map, { silent: true });
  if (!state.locked) zeichne('übersicht');
}

export function formatDate(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleDateString('de-DE');
}

/** „vor 5 Minuten", „gestern, 14:03" — knapp und ohne Rechnerei im Kopf. */
export function zeitLabel(iso) {
  const zeit = new Date(iso);
  if (Number.isNaN(zeit.getTime())) return '—';

  const minuten = Math.round((Date.now() - zeit.getTime()) / 60000);
  if (minuten < 1) return 'gerade eben';
  if (minuten < 60) return `vor ${minuten} Minute${minuten === 1 ? '' : 'n'}`;

  const heute = new Date().toDateString() === zeit.toDateString();
  const uhr = zeit.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' });
  if (heute) return `heute, ${uhr}`;
  return `${zeit.toLocaleDateString('de-DE', { day: '2-digit', month: '2-digit' })}, ${uhr}`;
}

/** Wann ein Eintrag zuletzt benutzt wurde — das Neueste aus Datei und App. */
export function lastUsed(e) {
  return Math.max(
    Date.parse(e.accessed) || 0,
    Date.parse(e.modified) || 0,
    usageMap()[e.id]?.at || 0
  );
}
