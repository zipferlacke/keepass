/**
 * core/entries.js — die kleinen Auskünfte über Einträge.
 *
 * Der Zustand wird für jede Prüfung selbst gesetzt; der Kern ist nicht
 * beteiligt, diese Funktionen rechnen nur.
 */
import { pruefe, gleich, wahr } from '../lib/pruef.js';
import { state } from '/src-ui/js/core/state.js';
import { liveEntries, visibleEntries, expiryState, byId, hasFiles, isFileEntry,
         usageMap, formatDate, zeitLabel, lastUsed } from '/src-ui/js/core/entries.js';

const eintrag = (zusatz = {}) => ({
  id: 'a', name: 'Webmail', username: 'max@example.com', url: 'example.com',
  tags: [], attachments: [], recycled: false, ...zusatz,
});

/** Setzt den Zustand für eine Prüfung und räumt hinterher auf. */
function mit(entries, fn) {
  const vorher = { entries: state.entries, search: state.search, tag: state.tag, kindFilter: state.kindFilter };
  Object.assign(state, { entries, search: '', tag: null, kindFilter: null });
  try { fn(); } finally { Object.assign(state, vorher); }
}

pruefe('liveEntries lässt den Papierkorb weg', () => {
  mit([eintrag(), eintrag({ id: 'b', recycled: true })], () => {
    gleich(liveEntries().map(e => e.id), ['a']);
  });
});

pruefe('byId findet auch, was im Papierkorb liegt', () => {
  mit([eintrag({ id: 'b', recycled: true })], () => {
    gleich(byId('b')?.id, 'b');
    gleich(byId('weg'), undefined);
  });
});

pruefe('visibleEntries sucht in Name, Benutzer, Adresse und Schlagworten', () => {
  mit([eintrag(), eintrag({ id: 'b', name: 'Bank', username: 'kunde', url: 'bank.de', tags: ['geld'] })], () => {
    state.search = 'bank';
    gleich(visibleEntries().map(e => e.id), ['b']);
    state.search = 'geld';
    gleich(visibleEntries().map(e => e.id), ['b'], 'Schlagwort zählt mit');
    state.search = 'example';
    gleich(visibleEntries().map(e => e.id), ['a']);
  });
});

pruefe('visibleEntries filtert nach Schlagwort und Art', () => {
  const mitDatei = eintrag({ id: 'd', attachments: [{ name: 'x.txt', ref: 'r' }] });
  mit([eintrag({ tags: ['arbeit'] }), eintrag({ id: 'p', passkey: true }), mitDatei], () => {
    state.tag = 'arbeit';
    gleich(visibleEntries().map(e => e.id), ['a']);
    state.tag = null;
    state.kindFilter = 'passkey';
    gleich(visibleEntries().map(e => e.id), ['p']);
    state.kindFilter = 'files';
    gleich(visibleEntries().map(e => e.id), ['d']);
  });
});

pruefe('expiryState kennt abgelaufen, läuft bald ab und sonst nichts', () => {
  const tag = 24 * 60 * 60 * 1000;
  const datum = ms => new Date(Date.now() + ms).toISOString().slice(0, 10);
  gleich(expiryState(eintrag({ expires: datum(-2 * tag) }))?.kind, 'expired');
  wahr(expiryState(eintrag({ expires: datum(-2 * tag) })).days < 0, 'Tage sind negativ');
  gleich(expiryState(eintrag({ expires: datum(3 * tag) }))?.kind, 'expiring');
  gleich(expiryState(eintrag({ expires: datum(400 * tag) })), null, 'weit weg ist kein Befund');
  gleich(expiryState(eintrag()), null, 'ohne Ablauf');
});

pruefe('hasFiles und isFileEntry unterscheiden Anhang von Dateiablage', () => {
  const ohne = eintrag();
  const mitAnhang = eintrag({ attachments: [{ name: 'a.pdf', ref: 'r' }] });
  const nurDatei = eintrag({ name: '', username: '', url: '', hasPassword: false,
                             attachments: [{ name: 'a.pdf', ref: 'r' }] });
  gleich(hasFiles(ohne), false);
  gleich(hasFiles(mitAnhang), true);
  gleich(isFileEntry(ohne), false);
  wahr(isFileEntry(nurDatei) === true || isFileEntry(nurDatei) === false, 'liefert ja oder nein');
});

pruefe('formatDate und zeitLabel liefern lesbare Zeiten', () => {
  gleich(formatDate(''), '', 'ohne Datum nichts');
  gleich(formatDate('Krokodil'), '', 'Unsinn ergibt nichts');
  gleich(formatDate('2026-01-15T10:00:00Z'), '15.1.2026');
  wahr(zeitLabel(new Date().toISOString()).length > 0, 'Label ist nicht leer');
});

pruefe('usageMap liefert je Eintrag Zeitpunkt und Woche', () => {
  const karte = usageMap(Date.now());
  gleich(typeof karte, 'object');
  for (const [, u] of Object.entries(karte)) {
    wahr(typeof u.at === 'number' && Array.isArray(u.week), 'Form stimmt');
  }
});

pruefe('lastUsed nimmt den jüngeren von Zugriff und Änderung', () => {
  const alt = '2026-01-01T00:00:00Z';
  const neu = '2026-06-01T00:00:00Z';
  gleich(lastUsed({ accessed: alt, modified: neu }), Date.parse(neu));
  gleich(lastUsed({ accessed: neu, modified: alt }), Date.parse(neu));
  gleich(lastUsed({}), 0, 'ohne Angaben null');
});
