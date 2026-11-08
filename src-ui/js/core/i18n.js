/**
 * i18n.js — die Texte der Oberfläche in der gewählten Sprache.
 *
 * Je Sprache **eine** Datei: `lang/de_DE.json`, `lang/en_GB.json` … (dieselben
 * Sprachen und Namen wie in wmap), die Liste in `lang/languages.json`. Oben stehen die
 * Seiten (Übersicht, Einträge, Einstellungen …), darunter ihre Bereiche,
 * darin die Texte. Ein Text heißt nach seinem Weg dorthin:
 *
 *     t('einstellungen.darstellung.titel')
 *
 * Deutsch ist die Grundlage: Fehlt ein Text in einer anderen Sprache, steht
 * der deutsche da — nie ein leerer Knopf. Fehlt er auch dort, steht der
 * Schlüssel da, damit es auffällt.
 *
 * Platzhalter in geschweiften Klammern: `t('…', { name: 'GitHub' })` setzt
 * `{name}` ein. Werte werden **nicht** entschärft — wer etwas aus der
 * Datenbank einsetzt, gibt es wie bisher durch `esc()`.
 *
 * Einzahl und Mehrzahl: Ist der Text ein Objekt (`{ "one": …, "other": … }`,
 * dazu nach Bedarf `"zero"`), wählt `{ n }` die passende Form.
 *
 * Feste Texte im HTML tragen `data-i18n="schlüssel"` (Inhalt) oder
 * `data-i18n-title`, `-placeholder`, `-aria-label`; `uebersetzeSeite()`
 * füllt sie beim Start.
 */

/** Was es gibt: `lang/languages.json`, Name jeweils in der eigenen Sprache. */
let sprachen = [];

/** Grundlage und Rückfall für fehlende Texte. */
const GRUNDLAGE = 'de_DE';
/** Gibt es die Sprache des Geräts nicht, gilt Englisch — wie in wmap. */
const UNBEKANNT = 'en_GB';

let sprache = GRUNDLAGE;
let texte = {};
let grundlage = {};

async function lade(datei) {
  // Im Bündel für die Vorschau liegen die Dateien eingebettet vor.
  if (globalThis.__EMBEDDED_LANG?.[datei]) return globalThis.__EMBEDDED_LANG[datei];
  const res = await fetch(new URL(`../../lang/${datei}.json`, import.meta.url), { cache: 'no-store' });
  if (!res.ok) throw new Error(`lang/${datei}.json nicht lesbar (${res.status}).`);
  return res.json();
}

/** Die Sprachen zur Auswahl: `[{ code, name }]`. */
export function sprachListe() {
  return sprachen;
}

/** Die Sprache, die `auto` meint: die des Geräts, sonst Englisch. */
export function systemSprache(codes = sprachen.map(l => l.code)) {
  const geraet = navigator.languages ?? [navigator.language];
  for (const tag of geraet) {
    const voll = String(tag ?? '').replace('-', '_');
    if (codes.includes(voll)) return voll;
  }
  for (const tag of geraet) {
    const kurz = String(tag ?? '').slice(0, 2).toLowerCase();
    const treffer = codes.find(c => c.slice(0, 2) === kurz);
    if (treffer) return treffer;
  }
  return codes.includes(UNBEKANNT) ? UNBEKANNT : GRUNDLAGE;
}

/**
 * Lädt die Texte. `wahl` ist der Wert aus den Einstellungen: `auto` oder
 * ein Code aus `languages.json` (etwa `en_GB`).
 */
export async function initI18n(wahl = 'auto') {
  sprachen = await lade('languages').catch(() => [{ code: GRUNDLAGE, name: 'Deutsch' }]);
  const codes = sprachen.map(l => l.code);
  const code = codes.includes(wahl) ? wahl : systemSprache(codes);
  grundlage = await lade(GRUNDLAGE);
  texte = code === GRUNDLAGE ? grundlage : await lade(code).catch(err => {
    console.error(err);
    return grundlage;
  });
  sprache = code;
  document.documentElement.lang = code.slice(0, 2);
  return code;
}

/** Kürzel der aktiven Sprache, etwa für Datumsangaben. */
export function aktiveSprache() {
  return sprache;
}

/** Gebietsschema für `toLocale…` und `Intl`. */
export function gebiet() {
  return sprache.replace('_', '-');
}

function suche(baum, weg) {
  let knoten = baum;
  for (const teil of weg) {
    if (knoten == null || typeof knoten !== 'object') return undefined;
    knoten = knoten[teil];
  }
  return knoten;
}

const mehrzahl = new Map();
function form(wert, n) {
  if (wert == null || typeof wert !== 'object' || Array.isArray(wert)) return wert;
  if (n === 0 && 'zero' in wert) return wert.zero;
  if (!mehrzahl.has(sprache)) mehrzahl.set(sprache, new Intl.PluralRules(gebiet()));
  return wert[mehrzahl.get(sprache).select(Number(n) || 0)] ?? wert.other;
}

/** Der Text zu `schluessel`, Platzhalter eingesetzt. */
export function t(schluessel, werte = {}) {
  const weg = schluessel.split('.');
  let wert = form(suche(texte, weg), werte.n);
  if (typeof wert !== 'string') wert = form(suche(grundlage, weg), werte.n);
  if (typeof wert !== 'string') {
    console.warn(`Text fehlt: ${schluessel}`);
    return schluessel;
  }
  return wert.replace(/\{(\w+)\}/g, (ganz, name) => (name in werte ? String(werte[name]) : ganz));
}

/** Eine Liste von Texten (etwa Absätze) — leer, wenn es keine gibt. */
export function tListe(schluessel) {
  const weg = schluessel.split('.');
  const wert = suche(texte, weg) ?? suche(grundlage, weg);
  return Array.isArray(wert) ? wert : [];
}

/** Zahl im Format der aktiven Sprache (1.234 bzw. 1,234). */
export function zahl(n) {
  return Number(n).toLocaleString(gebiet());
}

/** Füllt die festen Texte im HTML. */
export function uebersetzeSeite(wurzel = document) {
  for (const el of wurzel.querySelectorAll('[data-i18n]')) el.innerHTML = t(el.dataset.i18n);
  for (const attr of ['title', 'placeholder', 'aria-label', 'alt']) {
    for (const el of wurzel.querySelectorAll(`[data-i18n-${attr}]`)) {
      el.setAttribute(attr, t(el.getAttribute(`data-i18n-${attr}`)));
    }
  }
}
