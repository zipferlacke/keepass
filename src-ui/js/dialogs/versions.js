/**
 * versions.js — die Versionen der Datenbank.
 *
 * Zwei Dialoge: die Liste der aufgehobenen Stände und, dahinter, was ein
 * Stand geändert hat. Die Stände selbst führt der Kern (versions.rs).
 */

import * as vault from '../data/vault.js';
import { dialog, banner, closeHostDialog, zurueckZu } from '../ui/libs.js';
import { $, esc } from '../core/state.js';
import { renderAll, refreshFromVault } from '../core/render.js';
import { zeitLabel } from '../core/entries.js';

/* =========================================================
   Versionen
   ---------------------------------------------------------
   Der Kern hebt die letzten Stände der Datei auf. Gelesen wird die Liste
   wie ein Verlauf: Jeder Stand sagt, was er gegenüber dem davor geändert
   hat — nicht alles, was seitdem geschah. Das stand früher da und war
   nichtssagend: Der älteste Stand zählte jede spätere Änderung auf.

   „Zurücknehmen" macht eine einzelne Änderung rückgängig (der Eintrag
   kommt aus dem Stand davor), „Ganz auf diesen Stand zurück" setzt alles
   so, wie es hier war. Geschrieben wird danach wie bei jeder Änderung.
   ========================================================= */

/** Schrittvergleiche je Stand — Stände ändern sich nie, einmal reicht. */
const schritte = new Map();

function schritt(id) {
  if (!schritte.has(id)) {
    const p = vault.versionStep(id);
    // Ein Fehlschlag soll beim nächsten Öffnen neu versucht werden.
    p.catch(() => schritte.delete(id));
    schritte.set(id, p);
  }
  return schritte.get(id);
}

const ART = {
  neu: ['Dazugekommen', 'add_circle', 'neu'],
  geloescht: ['Gelöscht', 'remove_circle', 'gelöscht'],
  geaendert: ['Geändert', 'edit', 'geändert']
};

/** „geändert", „neu", „gelöscht" — oder genauer, wenn nur der Ordner wechselte. */
function wasPassiert(c) {
  if (c.kind === 'geaendert' && c.fields.length === 1 && c.fields[0].name === 'Ordner') {
    const nach = c.fields[0].after ?? '';
    if (nach === 'Papierkorb' || nach.startsWith('Papierkorb/')) return 'in den Papierkorb';
    if ((c.fields[0].before ?? '').startsWith('Papierkorb')) return 'wiederhergestellt';
    return 'verschoben';
  }
  return (ART[c.kind] ?? ART.geaendert)[2];
}

/** Eine Zeile für die Liste: „Intranet geändert · Webmail neu · +2". */
function schrittKurz(step) {
  if (!step.previous) return 'Ältester aufgehobener Stand';
  if (!step.changes.length) return 'Keine Einträge geändert';
  const teile = step.changes.slice(0, 2).map(c => `${c.name || '(ohne Titel)'} ${wasPassiert(c)}`);
  const rest = step.changes.length - teile.length;
  return teile.join(' · ') + (rest > 0 ? ` · +${rest}` : '');
}

export async function openVersionsDialog() {
  let staende = [];
  try {
    staende = await vault.versions();
  } catch (err) {
    banner(`Versionen nicht lesbar: ${err.message}`, 'error', 6000);
    return;
  }

  if (!staende.length) {
    banner('Noch keine Stände — der erste entsteht beim nächsten Öffnen oder Speichern.', 'info', 5000);
    return;
  }

  await dialog({
    title: 'Versionen',
    content: `
      <p class="dlg-note">Die letzten Stände der Datei, der jüngste oben. Unter jedem steht,
      was er geändert hat — antippen zeigt es genau und erlaubt das Zurücknehmen.</p>
      <div class="version-list">
        ${staende.map(v => `
          <button type="button" class="version-row" data-version="${esc(v.id)}">
            <span class="version-time">${esc(zeitLabel(v.at))}</span>
            <span class="version-reason">${esc(v.reason)}${v.current ? ' · <strong>aktueller Stand</strong>' : ''}</span>
            <span class="version-summary">…</span>
            <span class="msr">chevron_right</span>
          </button>`).join('')}
      </div>`,
    // Ohne Bestätigungsknopf fällt die Fußzeile weg — eine Liste braucht
    // keine.
    confirmText: null,
    cancelText: 'Schließen',
    // Ohne Fußzeile führt nur das Kreuz oben heraus.
    barRight: { icon: 'close', title: 'Schließen', action: 'cancel' },
    // `onInsert` bekommt die Kennung, nicht das Element — der Dialog steht
    // zu diesem Zeitpunkt schon im Dokument.
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
 * Trägt die Zusammenfassungen nach, einen Stand nach dem anderen: Jeder
 * Vergleich entschlüsselt zwei Dateien, und das dauert — auf dem Handy
 * bis zu einer Sekunde. Nacheinander erscheinen die oberen zuerst.
 */
async function fuelleZusammenfassungen(host) {
  for (const row of host?.querySelectorAll('[data-version]') ?? []) {
    const ziel = row.querySelector('.version-summary');
    try {
      ziel.textContent = schrittKurz(await schritt(row.dataset.version));
    } catch {
      ziel.textContent = 'Nicht lesbar';
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
    banner(`Der Stand ließ sich nicht vergleichen: ${err.message}`, 'error', 6000);
    return;
  }

  const liste = step.changes.map(c => {
    const [label, icon] = ART[c.kind] ?? ART.geaendert;
    const felder = c.fields.map(f => f.before == null && f.after == null
      ? `<li>${esc(f.name)} geändert</li>`
      : `<li>${esc(f.name)}: <del>${esc(f.before || '—')}</del> <span class="msr">arrow_forward</span> ${esc(f.after || '—')}</li>`).join('');
    return `<div class="version-change" data-kind="${c.kind}">
      <div class="version-change-head">
        <span class="msr">${icon}</span>
        <strong>${esc(c.name || '(ohne Titel)')}</strong>
        <small>${esc(label)}${c.folder ? ` · ${esc(c.folder)}` : ''}</small>
        <button type="button" class="button" data-undo="${esc(c.id)}"
                title="Den Eintrag so zurückholen, wie er vor diesem Stand war">Zurücknehmen</button>
      </div>
      ${felder ? `<ul class="version-fields">${felder}</ul>` : ''}
    </div>`;
  }).join('');

  const inhalt = !step.previous
    ? `<p class="dlg-note">Das ist der älteste aufgehobene Stand — was er gegenüber dem davor
       geändert hat, lässt sich nicht mehr sagen.</p>`
    : step.changes.length
      ? `<div class="version-changes">${liste}</div>`
      : '<p class="dlg-note">An den Einträgen hat dieser Stand nichts geändert.</p>';

  await dialog({
    title: `Stand ${zeitLabel(stand.at)}`,
    // Oben links „Zurück": von einem Stand wieder in die Liste, ohne über
    // die Einstellungen zu laufen.
    onBack: zurueckZu(openVersionsDialog),
    content: `
      <p class="dlg-note"><strong>${esc(stand.reason)}.</strong> ${step.previous && step.changes.length
        ? 'Das hat dieser Stand gegenüber dem davor geändert.' : ''}
      ${stand.current ? 'So liegt die Datei gerade da.' : `„Ganz auf diesen Stand zurück" setzt alle
      Einträge so, wie sie hier waren — was danach kam, bleibt in den Versionen erhalten.`}</p>
      ${inhalt}`,
    // Auf den aktuellen Stand zurück gibt es nicht — dann keine Fußzeile,
    // und oben das Kreuz.
    confirmText: stand.current ? null : 'Ganz auf diesen Stand zurück',
    cancelText: 'Schließen',
    barRight: stand.current ? { icon: 'close', title: 'Schließen', action: 'cancel' } : null,
    onInsert: id => {
      const host = document.getElementById(String(id));
      host?.querySelectorAll('[data-undo]').forEach(btn => btn.addEventListener('click', async () => {
        btn.disabled = true;
        await zurueckholen(step.previous, [btn.dataset.undo]);
        btn.textContent = 'Zurückgenommen';
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
      ? 'Eintrag zurückgeholt und gespeichert.'
      : `${zahl} Eintr${zahl === 1 ? 'ag' : 'äge'} zurückgeholt und gespeichert.`, 'success');
  } catch (err) {
    banner(`Zurückholen fehlgeschlagen: ${err.message}`, 'error', 6000);
  }
}
