/**
 * core/state.js — der gemeinsame Zustand und die drei Handgriffe.
 */
import { pruefe, gleich, wahr } from '../lib/pruef.js';
import { state, $, $$, esc, SECRET_MASK, VIEW_TITLES } from '/src-ui/js/core/state.js';

pruefe('esc entschärft alles, was HTML durcheinanderbrächte', () => {
  gleich(esc('<script>alert("x")</script>'),
         '&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;');
  gleich(esc("Tom & Jerry's"), 'Tom &amp; Jerry&#39;s');
});

pruefe('esc macht aus nichts einen leeren Text', () => {
  gleich(esc(null), '');
  gleich(esc(undefined), '');
  gleich(esc(0), '0');
});

pruefe('$ und $$ finden Elemente im Dokument', () => {
  const h = document.createElement('div');
  h.innerHTML = '<p class="x">eins</p><p class="x">zwei</p>';
  document.body.append(h);
  wahr($('.x') !== null, '$ findet das erste');
  gleich($$('.x').length, 2);
  gleich(Array.isArray($$('.x')), true, '$$ liefert ein echtes Feld');
  h.remove();
});

pruefe('der Zustand startet auf der Übersicht und gesperrt', () => {
  gleich(state.view, 'home');
  gleich(state.locked, true);
  wahr(state.entries.length === 0, 'noch keine Einträge');
});

pruefe('jede Ansicht hat einen Titel, die Maske ist nicht leer', () => {
  for (const name of ['home', 'passwords', 'totp', 'security', 'settings']) {
    wahr(Boolean(VIEW_TITLES[name]), `Titel für ${name}`);
  }
  wahr(SECRET_MASK.length > 0, 'Maske');
});
