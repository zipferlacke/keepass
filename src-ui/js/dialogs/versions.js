/**
 * versions.js — die Versionen der Datenbank.
 *
 * Zwei Dialoge: die Liste der aufgehobenen Stände und, dahinter, was ein
 * Stand geändert hat. Die Stände selbst führt der Kern (versions.rs).
 */

import * as vault from '../data/vault.js';
import { dialog, banner, closeHostDialog, zurueckZu } from '../ui/libs.js';
import { $, esc } from '../core/state.js';
import { t } from '../core/i18n.js';
import { renderAll, refreshFromVault } from '../core/render.js';
import { zeitLabel } from '../core/entries.js';

/* =========================================================
   Versionen
   ---------------------------------------------------------
   Der Kern hebt die letzten Stände der Datei auf. Jeder Stand zeigt, was
   er gegenüber dem vorigen geändert hat.

   „Zurücknehmen" macht eine einzelne Änderung rückgängig (der Eintrag
   kommt aus dem Stand davor), „Ganz auf diesen Stand zurück" stellt den
   gesamten Stand wieder her. Danach wird wie bei jeder Änderung gespeichert.
   ========================================================= */

/** Zwischengespeicherte Schrittvergleiche je Stand (Stände sind unveränderlich). */
const schritte = new Map();

function schritt(id) {
  if (!schritte.has(id)) {
    const p = vault.versionStep(id);
    // Fehlgeschlagene Vergleiche werden nicht zwischengespeichert.
    p.catch(() => schritte.delete(id));
    schritte.set(id, p);
  }
  return schritte.get(id);
}

/** Woher eine Änderung in einem zusammengeführten Stand kam. */
function herkunft(origin) {
  // i18n: dialoge.versionen.herkunft.extern dialoge.versionen.herkunft.hier dialoge.versionen.herkunft.beide
  return ['extern', 'hier', 'beide'].includes(origin) ? t(`dialoge.versionen.herkunft.${origin}`) : origin;
}

/** [Überschrift, Symbol, Kurzform] je Art der Änderung. */
function art(kind) {
  switch (kind) {
    case 'neu': return [t('dialoge.versionen.art.neu.label'), 'add_circle', t('dialoge.versionen.art.neu.kurz')];
    case 'geloescht': return [t('dialoge.versionen.art.geloescht.label'), 'remove_circle', t('dialoge.versionen.art.geloescht.kurz')];
    default: return [t('dialoge.versionen.art.geaendert.label'), 'edit', t('dialoge.versionen.art.geaendert.kurz')];
  }
}

/** „geändert", „neu", „gelöscht" — oder genauer, wenn nur der Ordner wechselte. */
function wasPassiert(c) {
  if (c.kind === 'geaendert' && c.fields.length === 1 && c.fields[0].name === 'Ordner') {
    const nach = c.fields[0].after ?? '';
    if (nach === 'Papierkorb' || nach.startsWith('Papierkorb/')) return t('dialoge.versionen.passiert.papierkorb');
    if ((c.fields[0].before ?? '').startsWith('Papierkorb')) return t('dialoge.versionen.passiert.wiederhergestellt');
    return t('dialoge.versionen.passiert.verschoben');
  }
  return art(c.kind)[2];
}

/** Eine Zeile für die Liste: „Intranet geändert · Webmail neu · +2". */
function schrittKurz(step) {
  if (!step.previous) return t('dialoge.versionen.kurz.aeltester');
  if (!step.changes.length) return t('dialoge.versionen.kurz.keine');
  const teile = step.changes.slice(0, 2).map(c => `${c.name || t('dialoge.versionen.ohneTitel')} ${wasPassiert(c)}`);
  const rest = step.changes.length - teile.length;
  return teile.join(' · ') + (rest > 0 ? ` · +${rest}` : '');
}

export async function openVersionsDialog() {
  let staende = [];
  try {
    staende = await vault.versions();
  } catch (err) {
    banner(t('dialoge.versionen.liste.fehler', { fehler: err.message }), 'error', 6000);
    return;
  }

  if (!staende.length) {
    banner(t('dialoge.versionen.liste.leer'), 'info', 5000);
    return;
  }

  await dialog({
    title: t('dialoge.versionen.liste.titel'),
    content: `
      <p class="dlg-note">${t('dialoge.versionen.liste.hinweis')}</p>
      <div class="version-list">
        ${staende.map(v => `
          <button type="button" class="version-row" data-version="${esc(v.id)}">
            <span class="version-time">${esc(zeitLabel(v.at))}</span>
            <span class="version-reason">${esc(v.reason)}${v.current ? ` · <strong>${t('dialoge.versionen.liste.aktuell')}</strong>` : ''}</span>
            <span class="version-summary">…</span>
            <span class="msr">chevron_right</span>
          </button>`).join('')}
      </div>`,
    // Keine Fußzeile; die Liste braucht keinen Bestätigungsknopf.
    confirmText: null,
    cancelText: t('allgemein.knoepfe.schliessen'),
    // Schließen über das Kreuz oben.
    barRight: { icon: '<span class="msr">close</span>', title: t('allgemein.knoepfe.schliessen'), action: 'cancel' },
    // `onInsert` erhält die Kennung des bereits eingefügten Dialogs.
    onInsert: id => {
      const host = document.getElementById(String(id));
      host?.querySelectorAll('[data-version]').forEach(btn => btn.addEventListener('click', () => {
        const stand = staende.find(v => v.id === btn.dataset.version);
        closeHostDialog(btn, false);
        setTimeout(() => openVersionChangesDialog(stand), 50);
      }));
      fuelleZusammenfassungen(host);
    }
  });
}

/**
 * Lädt die Zusammenfassungen nacheinander nach, die oberen zuerst. Jeder
 * Vergleich entschlüsselt zwei Dateien (auf dem Handy bis zu einer Sekunde).
 */
async function fuelleZusammenfassungen(host) {
  for (const row of host?.querySelectorAll('[data-version]') ?? []) {
    const ziel = row.querySelector('.version-summary');
    try {
      ziel.textContent = schrittKurz(await schritt(row.dataset.version));
    } catch {
      ziel.textContent = t('dialoge.versionen.liste.nichtLesbar');
    }
    if (!host.isConnected) return;
  }
}

async function openVersionChangesDialog(stand) {
  if (!stand) return;

  let step;
  try {
    step = await schritt(stand.id);
  } catch (err) {
    banner(t('dialoge.versionen.stand.vergleichFehler', { fehler: err.message }), 'error', 6000);
    return;
  }

  const liste = step.changes.map(c => {
    const [label, icon] = art(c.kind);
    const felder = c.fields.map(f => f.before == null && f.after == null
      ? `<li>${t('dialoge.versionen.stand.feldGeaendert', { name: esc(f.name) })}</li>`
      : `<li>${esc(f.name)}: <del>${esc(f.before || '—')}</del> <span class="msr">arrow_forward</span> ${esc(f.after || '—')}</li>`).join('');
    return `<div class="version-change" data-kind="${c.kind}">
      <div class="version-change-head">
        <span class="msr">${icon}</span>
        <strong>${esc(c.name || t('dialoge.versionen.ohneTitel'))}</strong>
        <small>${esc(label)}${c.folder ? ` · ${esc(c.folder)}` : ''}${c.origin ? ` · ${esc(herkunft(c.origin))}` : ''}</small>
        <button type="button" class="button" data-undo="${esc(c.id)}"
                title="${t('dialoge.versionen.stand.zuruecknehmenTitel')}">${t('dialoge.versionen.stand.zuruecknehmen')}</button>
      </div>
      ${felder ? `<ul class="version-fields">${felder}</ul>` : ''}
    </div>`;
  }).join('');

  const inhalt = !step.previous
    ? `<p class="dlg-note">${t('dialoge.versionen.stand.aeltesterHinweis')}</p>`
    : step.changes.length
      ? `<div class="version-changes">${liste}</div>`
      : `<p class="dlg-note">${t('dialoge.versionen.stand.nichtsGeaendert')}</p>`;

  await dialog({
    title: t('dialoge.versionen.stand.titel', { zeit: zeitLabel(stand.at) }),
    // „Zurück" führt von einem Stand in die Liste.
    onBack: zurueckZu(openVersionsDialog),
    content: `
      <p class="dlg-note"><strong>${esc(stand.reason)}.</strong> ${step.previous && step.changes.length
        ? t('dialoge.versionen.stand.gegenueber') : ''}
      ${stand.current ? t('dialoge.versionen.stand.liegtDa') : t('dialoge.versionen.stand.ganzZurueckHinweis')}</p>
      ${inhalt}`,
    // Beim aktuellen Stand entfällt „Ganz zurück"; es bleibt das Kreuz oben.
    confirmText: stand.current ? null : t('dialoge.versionen.stand.ganzZurueck'),
    cancelText: t('allgemein.knoepfe.schliessen'),
    barRight: stand.current ? { icon: '<span class="msr">close</span>', title: t('allgemein.knoepfe.schliessen'), action: 'cancel' } : null,
    onInsert: id => {
      const host = document.getElementById(String(id));
      host?.querySelectorAll('[data-undo]').forEach(btn => btn.addEventListener('click', async () => {
        btn.disabled = true;
        await zurueckholen(step.previous, [btn.dataset.undo]);
        btn.textContent = t('dialoge.versionen.stand.zurueckgenommen');
      }));
    }
  }).then(res => {
    if (res?.submit ?? res) return zurueckholen(stand.id, null);
  });
}

/** Holt zurück und schreibt die Datei. */
async function zurueckholen(id, entries) {
  try {
    const zahl = await vault.versionRestore(id, entries);
    await vault.commit();
    await refreshFromVault();
    renderAll({ ohne: ['einstellungen'] });
    banner(entries
      ? t('dialoge.versionen.zurueckholen.eintrag')
      : t('dialoge.versionen.zurueckholen.eintraege', { n: zahl }), 'success');
  } catch (err) {
    banner(t('dialoge.versionen.zurueckholen.fehler', { fehler: err.message }), 'error', 6000);
  }
}
