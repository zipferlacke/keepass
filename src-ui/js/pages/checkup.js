/**
 * checkup.js — der Sicherheitscheck.
 *
 * Drei Fragen an die Datenbank: Steckt ein Passwort in einem bekannten
 * Leck (HIBP, nur als Hash-Präfix gefragt), gehört eine Adresse zu einem
 * Datenleck (XposedOrNot), und was liegt seit Jahren unbenutzt herum.
 * Dazu die Befunde aus dem Kern: schwach, mehrfach benutzt, abgelaufen.
 *
 * Geprüft wird auf Wunsch oder in Abständen; das Ergebnis bleibt pro
 * Datenbank in den Einstellungen stehen, damit die Seite nach dem Öffnen
 * nicht leer ist.
 */

import * as vault from '../data/vault.js';
import * as settings from '../data/settings.js';
import { checkPwnedByHash, checkEmailBreached, breachAnalytics, accountDeletionIndex,
         findDeletion, passwordStrength as localStrength } from '../data/security.js';
import { dialog, banner } from '../ui/libs.js';
import { state, $, $$, esc } from '../core/state.js';
import { liveEntries, expiryState, usageMap, lastUsed } from '../core/entries.js';
import { zeichne, refreshFromVault, nachStrukturaenderung } from '../core/render.js';
import { renderEntryTable, runRowAction } from './entries.js';
import { openEntryDialog } from '../dialogs/entry.js';
import { invoke } from '../core/platform.js';

/* =========================================================
   Sicherheitscheck
   ========================================================= */
export function renderSecurity() {
  const pwCheck = settings.get('checks.passwordBreach', true);
  const mailCheck = settings.get('checks.emailBreach', true);

  const live = liveEntries();
  const leaked = live.filter(e => state.pwned.get(e.id)?.found);
  const weak = settings.get('checks.passwordStrength', true)
    ? live.filter(e => (state.strength.get(e.id)?.score ?? 9) < 2)
    : [];
  const reused = live.filter(e => state.reused.has(e.id));
  const expiring = live.filter(e => expiryState(e));
  const inactive = inactiveEntries(live);
  const mailCount = state.emailFindings.reduce((a, f) => a + openBreaches(f).length, 0);

  const stats = [
    { key: 'leaked', num: pwCheck ? leaked.length : '–', label: 'geleakte Passwörter', tone: leaked.length ? 'bad' : 'ok' },
    { key: 'weak', num: weak.length, label: 'schwache Passwörter', tone: weak.length ? 'warn' : 'ok' },
    { key: 'reused', num: reused.length, label: 'mehrfach genutzt', tone: reused.length ? 'warn' : 'ok' },
    { key: 'expiring', num: expiring.length, label: 'abgelaufen / bald fällig', tone: expiring.length ? 'warn' : 'ok' },
    { key: 'mail', num: mailCheck ? mailCount : '–', label: 'E-Mail-Leaks', tone: mailCount ? 'bad' : 'ok' },
    { key: 'inactive', num: inactive.length, label: 'lange nicht genutzt', tone: inactive.length ? 'warn' : 'ok' }
  ];

  const last = settings.get('checks.lastRunAt', null);

  const group = (id, title, items) =>
    secSection(id, title, items.length, `<div class="findings-table" data-list="${id}"></div>`);

  const groups = [
    pwCheck ? { id: 'leaked', title: 'Geleakte Passwörter', items: leaked, empty: 'Keine Treffer' } : null,
    { id: 'weak', title: 'Schwache Passwörter', items: weak, empty: 'Alle Passwörter ausreichend stark' },
    { id: 'reused', title: 'Mehrfach genutzte Passwörter', items: reused, empty: 'Keine Mehrfachnutzung' },
    { id: 'expiring', title: 'Ablaufdaten', items: expiring, empty: 'Kein Passwort fällig' }
  ].filter(Boolean);

  $('#security-body').innerHTML = `
    <div class="security-layout">
      <aside class="security-stats">
        <div class="security-elements">
          ${stats.map(st => `
          <button class="stat" data-tone="${st.tone}" data-jump="sec-${st.key}">
            <span class="stat-num">${st.num}</span>
            <span class="stat-label">${st.label}</span>
          </button>`).join('')}
        </div>
        <div class="security-check">
          <button class="button hightlight" data-shape="full" id="btn-run-check" ${state.checkRunning ? 'disabled' : ''}>
            ${state.checkRunning
              ? '<span class="busy-dots" data-inline aria-hidden="true"><i></i><i></i><i></i></span>'
              : '<span class="msr">shield_lock</span>'}
            ${state.checkRunning ? 'Prüfe …' : 'Jetzt prüfen'}
          </button>
          <p class="security-last">${last ? `Zuletzt: ${new Date(last).toLocaleString('de-DE')}` : 'Noch nicht geprüft'}</p>
        </div>
      </aside>

      <div class="security-findings">
        ${groups.map(g => group(g.id, g.title, g.items)).join('')}
        ${mailCheck ? renderMailFindings() : ''}
        ${renderInactive(inactive)}
      </div>
    </div>`;

  // Befunde in derselben Darstellung wie überall
  for (const g of groups) {
    const box = $(`.findings-table[data-list="${g.id}"]`);
    if (box) renderEntryTable(box, g.items, { variant: 'findings' });
  }

  $('#btn-run-check')?.addEventListener('click', () => runSecurityCheck());

  $$('#security-body [data-jump]').forEach(btn => btn.addEventListener('click', () => {
    const target = document.getElementById(btn.dataset.jump);
    if (target?.tagName === 'DETAILS') target.open = true;
    target?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }));

  // Direkt aus dem Befund heraus bearbeiten
  $$('#security-body [data-edit]').forEach(btn =>
    btn.addEventListener('click', () => openEntryDialog(btn.dataset.edit)));

  // Lecks einer Adresse als erledigt abhaken
  $$('#security-body [data-ack]').forEach(btn => btn.addEventListener('click', async () => {
    const f = state.emailFindings.find(x => x.email === btn.dataset.ack);
    if (!f) return;
    const ack = { ...settings.get('checks.breachAck', {}) };
    ack[f.email] = [...new Set([...(ack[f.email] ?? []), ...f.breaches.map(b => b.name)])];
    await settings.set('checks.breachAck', ack, { silent: true });
    renderSecurity();
    zeichne('übersicht');
  }));

  // Inaktive Einträge: noch in Gebrauch, oder weg damit
  $$('#security-body [data-still-used]').forEach(btn => btn.addEventListener('click', async () => {
    btn.disabled = true;
    try {
      await vault.markAccessed([btn.dataset.stillUsed], true);
      await refreshFromVault();
      renderSecurity();
      banner('Vermerkt — der Eintrag gilt wieder als genutzt.', 'success', 3000);
    } catch (err) {
      btn.disabled = false;
      banner(err.message, 'error', 6000);
    }
  }));
  $$('#security-body [data-remove]').forEach(btn =>
    btn.addEventListener('click', () => runRowAction('delete', btn.dataset.remove)));
  $$('#security-body [data-account-delete]').forEach(btn =>
    btn.addEventListener('click', () => deleteAccountFlow(btn.dataset.accountDelete, btn.dataset.url)));
}

/**
 * Ein Abschnitt des Sicherheitschecks: aufgeklappt, wenn etwas drinsteht,
 * sonst zu — dann steht klein daneben, dass nichts zu tun ist.
 */
function secSection(id, title, count, body) {
  return `
    <details class="sec-group" id="sec-${id}" ${count ? 'open' : ''}>
      <summary>
        <span class="sec-title">${title}</span>
        ${count
          ? `<span class="sec-count">${count}</span>`
          : `<small class="sec-ok"><span class="msr">check_circle</span>Keine Treffer – nichts zu tun</small>`}
      </summary>
      ${count ? `<div class="sec-body">${body}</div>` : ''}
    </details>`;
}

/* ---------- E-Mail-Datenlecks ---------- */

/** Die Lecks einer Adresse, die noch nicht als erledigt abgehakt sind. */
export function countProblems() {
  let n = 0;
  for (const e of state.entries) {
    if (state.pwned.get(e.id)?.found) n++;
    if (state.reused.has(e.id)) n++;
    if (expiryState(e)) n++;
  }
  return n + state.emailFindings.reduce((a, f) => a + openBreaches(f).length, 0);
}

function openBreaches(f) {
  const done = settings.get('checks.breachAck', {})[f.email] ?? [];
  return f.breaches.filter(b => !done.includes(b.name));
}

/** Was die Leck-Datenbank auf Englisch meldet, auf Deutsch. */
const LEAK_DATA = {
  'Email addresses': 'E-Mail-Adresse', 'Passwords': 'Passwort', 'Usernames': 'Benutzername',
  'Names': 'Name', 'Phone numbers': 'Telefonnummer', 'Physical addresses': 'Postanschrift',
  'Dates of birth': 'Geburtsdatum', 'IP addresses': 'IP-Adresse', 'Genders': 'Geschlecht',
  'Geographic locations': 'Wohnort', 'Credit cards': 'Kreditkarte', 'Partial credit card data': 'Teile der Kreditkarte',
  'Bank account numbers': 'Kontonummer', 'Security questions and answers': 'Sicherheitsfragen',
  'Auth Tokens': 'Anmelde-Token', 'Social media profiles': 'Social-Media-Profil', 'Private Messages': 'Private Nachrichten',
  'Browser user agent details': 'Browserdaten', 'Purchases': 'Einkäufe', 'Job titles': 'Beruf', 'Employers': 'Arbeitgeber'
};

/** Einträge, die zum Dienst eines Lecks gehören — dort ist etwas zu tun. */
function entriesForBreach(b) {
  const domain = (b.domain || '').toLowerCase();
  const name = (b.name || '').toLowerCase();
  return liveEntries().filter(e => {
    const host = (() => { try { return new URL(e.url.includes('://') ? e.url : `https://${e.url}`).hostname.toLowerCase(); } catch { return ''; } })();
    return (domain && host && (host === domain || host.endsWith(`.${domain}`)))
      || (name.length > 3 && e.name.toLowerCase().includes(name));
  });
}

/**
 * Je Adresse: welche Lecks, was dabei abgeflossen ist, was zu tun ist —
 * und der Knopf zum passenden Eintrag.
 *
 * Die Adresse selbst kann man nicht „ändern" wie ein Passwort, und das muss
 * man auch nicht. Gefährlich ist, was **mit** ihr abgeflossen ist. Darum
 * richtet sich der Rat nach den Daten jedes einzelnen Lecks.
 */
function renderMailFindings() {
  const affected = state.emailFindings.filter(f => openBreaches(f).length);
  const done = state.emailFindings.filter(f => f.breaches.length && !openBreaches(f).length);

  const breachRow = b => {
    const data = (b.data ?? []).map(d => LEAK_DATA[d] ?? d);
    const pw = (b.data ?? []).includes('Passwords');
    const plain = ['plaintext', 'easytocrack'].includes(b.passwordRisk);
    const entries = entriesForBreach(b);
    const todo = [];
    if (pw) todo.push(plain
      ? '<strong>Passwort sofort ändern</strong> — es war im Klartext oder leicht zu knacken gespeichert.'
      : 'Passwort ändern — es lag verschlüsselt vor, sicher ist das aber nicht.');
    if (pw && entries.some(e => state.reused.has(e.id))) todo.push('Dasselbe Passwort nutzt du noch woanders — dort ebenfalls ändern.');
    if ((b.data ?? []).some(d => /Phone/.test(d))) todo.push('Mit SMS- und Anruf-Betrug im Namen dieses Dienstes rechnen.');
    if ((b.data ?? []).some(d => /Physical|Dates of birth/.test(d))) todo.push('Anschrift oder Geburtsdatum sind bekannt — bei Rückfragen „zur Bestätigung" skeptisch sein.');
    if ((b.data ?? []).some(d => /credit|Bank/i.test(d))) todo.push('Kontoauszüge und Kreditkarte auf fremde Buchungen prüfen.');
    if (!pw && !todo.length) todo.push('Kein Passwort betroffen. Wichtig ist hier vor allem: Mails im Namen dieses Dienstes kritisch lesen.');

    return `<div class="breach">
      <div class="breach-head"><span>${esc(b.name)}</span><span class="breach-meta">${esc(b.year || '')}</span></div>
      ${data.length ? `<div class="breach-meta">Abgeflossen: ${esc(data.join(', '))}</div>` : ''}
      <ul class="finding-advice">${todo.map(t => `<li>${t}</li>`).join('')}</ul>
      ${entries.length ? `<div class="finding-actions">${entries.map(e =>
        `<button type="button" class="button" data-edit="${e.id}"><span class="msr">edit</span>&nbsp;${esc(e.name)} öffnen</button>`).join('')}</div>` : ''}
    </div>`;
  };

  const count = affected.reduce((n, f) => n + openBreaches(f).length, 0);
  return secSection('mail', 'E-Mail-Datenlecks', count, `
      <details class="finding" data-tone="info">
        <summary class="finding-title"><span class="msr">help</span>Was bedeutet ein Treffer — und was ist zu tun?</summary>
        <div class="finding-advice">
          Deine Adresse stand in Daten, die bei einem Dienst gestohlen und veröffentlicht wurden. Das heißt nicht, dass jemand
          in deinem Postfach war. Die Adresse lässt sich nicht zurückholen — das musst du auch nicht. Entscheidend ist, <em>was</em>
          zusammen mit ihr abgeflossen ist; danach richtet sich unten der Rat zu jedem einzelnen Leck.
          <ol>
            <li>Beim betroffenen Dienst das Passwort ändern — und überall dort, wo du dasselbe benutzt.</li>
            <li>Wo möglich die Zwei-Faktor-Anmeldung einschalten. WKeePass kann die Codes gleich mit verwalten.</li>
            <li>Mit Phishing rechnen: Angreifer schreiben gezielt an geleakte Adressen, gern im Namen genau dieses Dienstes.</li>
            <li>Konten, die du nicht mehr brauchst, beim Dienst löschen — ein vergessenes Konto ist ein offenes Konto.</li>
            <li>Für neue Anmeldungen Alias-Adressen nutzen, wenn dein Mail-Anbieter das kann. Dann trifft ein Leck nur noch eine davon.</li>
          </ol>
          Hast du alles erledigt, hake die Adresse ab. Neue Lecks meldet die nächste Prüfung wieder.
        </div>
      </details>
      ${affected.map(f => `
        <div class="finding" data-tone="bad">
          <div class="finding-title"><span class="msr">mail</span>${esc(f.email)}
            <small>&nbsp;· ${openBreaches(f).length === 1 ? 'ein Leck' : `${openBreaches(f).length} Lecks`}</small></div>
          <div class="breach-list">${openBreaches(f).map(breachRow).join('')}</div>
          <div class="finding-actions">
            <button type="button" class="button" data-ack="${esc(f.email)}"><span class="msr">task_alt</span>&nbsp;Erledigt</button>
          </div>
        </div>`).join('')}
    ${done.length ? `<p class="security-last">Erledigt: ${done.map(f => esc(f.email)).join(', ')}</p>` : ''}`);
}

/* ---------- Inaktive Einträge ---------- */

/** Nach so langer Zeit ohne Nutzung gilt ein Eintrag als inaktiv. */
const INACTIVE_AFTER = 2 * 365 * 24 * 60 * 60 * 1000;

function inactiveEntries(live) {
  const now = Date.now();
  return live
    .filter(e => { const t = lastUsed(e); return t > 0 && now - t > INACTIVE_AFTER; })
    .sort((a, b) => lastUsed(a) - lastUsed(b));
}

/** Wie mühsam das Löschen laut JustDeleteMe ist. */
const LOESCH_AUFWAND = {
  easy: 'geht direkt auf der Seite',
  medium: 'ein paar Schritte mehr',
  hard: 'nur über den Support',
  impossible: 'bietet keine Löschung an'
};

/**
 * Zugänge, die seit über zwei Jahren niemand angefasst hat. Entweder
 * braucht man sie nicht mehr — dann Konto beim Dienst löschen und Eintrag
 * entfernen —, oder sie werden noch gebraucht, dann ein Klick.
 *
 * Für bekannte Dienste führt ein Knopf direkt auf deren Löschseite
 * (Liste von JustDeleteMe, siehe security.js). Kommt der Nutzer von dort
 * zurück, fragt die App, ob auch der Eintrag weg soll.
 */
function renderInactive(items) {
  const when = e => new Date(lastUsed(e)).toLocaleDateString('de-DE', { month: 'long', year: 'numeric' });
  const host = url => { try { return new URL(url.includes('://') ? url : `https://${url}`).hostname.replace(/^www\./, ''); } catch { return ''; } };

  // Die Löschliste kommt aus dem Netz; beim ersten Zeichnen ist sie noch
  // nicht da. Dann nachladen und die Seite einmal neu zeichnen.
  if (items.length && !state.deletionIndex) {
    accountDeletionIndex().then(index => {
      state.deletionIndex = index;
      if (state.view === 'security') renderSecurity();
    });
  }

  return secSection('inactive', 'Lange nicht genutzt', items.length, `
      <p class="section-note">Diese Zugänge hast du seit über zwei Jahren nicht benutzt. Brauchst du einen nicht mehr, lösche zuerst
        das Konto beim Dienst und dann den Eintrag — ein vergessenes Konto mit altem Passwort ist ein beliebtes Ziel.
        Wird er noch gebraucht, genügt „Noch in Gebrauch".</p>
      ${items.map(e => {
        const del = findDeletion(state.deletionIndex, e.url);
        const site = host(e.url || '');
        return `
        <div class="finding inactive-item" data-tone="warn">
          <div class="inactive-head">
            <div class="finding-title"><span class="msr">schedule</span>${esc(e.name)}</div>
            <div class="inactive-meta">
              ${e.username ? `<span><span class="msr">person</span>${esc(e.username)}</span>` : ''}
              ${site ? `<span><span class="msr">link</span>${esc(site)}</span>` : ''}
            </div>
          </div>
          <div class="finding-text">Zuletzt genutzt: ${esc(when(e))}${del ? ` · Konto löschen ${esc(LOESCH_AUFWAND[del.difficulty] ?? '')}` : ''}</div>
          <div class="finding-actions">
            <button type="button" class="button" data-edit="${e.id}"><span class="msr">edit</span>&nbsp;Öffnen</button>
            <button type="button" class="button" data-still-used="${e.id}"><span class="msr">check</span>&nbsp;Noch in Gebrauch</button>
            ${del && del.difficulty !== 'impossible'
              ? `<button type="button" class="button" data-account-delete="${e.id}" data-url="${esc(del.url)}"><span class="msr">person_remove</span>&nbsp;Konto löschen</button>`
              : site ? `<button type="button" class="button" data-account-delete="${e.id}" data-url="${esc(e.url.includes('://') ? e.url : `https://${e.url}`)}"><span class="msr">open_in_new</span>&nbsp;Zur Seite</button>` : ''}
            <button type="button" class="button" data-remove="${e.id}"><span class="msr">delete</span>&nbsp;Eintrag löschen</button>
          </div>
        </div>`;
      }).join('')}`);
}

/**
 * Auf die Löschseite des Dienstes springen. Kommt der Nutzer zurück, die
 * Frage, ob das Konto weg ist — dann gleich auch den Eintrag entfernen.
 * Das Passwort braucht man dort meist noch einmal; deshalb erst danach.
 */
async function deleteAccountFlow(id, url) {
  const entry = vault.getEntry(id);
  if (!entry) return;
  try { await vault.openLink(url); } catch (err) { banner(err.message, 'error', 6000); return; }

  await new Promise(resolve => {
    const back = () => {
      if (document.visibilityState !== 'visible') return;
      document.removeEventListener('visibilitychange', back);
      window.removeEventListener('focus', back);
      resolve();
    };
    // Kurz warten: Direkt nach dem Öffnen meldet der Webview noch „sichtbar".
    setTimeout(() => {
      document.addEventListener('visibilitychange', back);
      window.addEventListener('focus', back);
    }, 1500);
  });

  const res = await dialog({
    title: 'Konto gelöscht?',
    content: `<p>Hast du das Konto bei <strong>${esc(entry.name)}</strong> gelöscht? Dann kann auch der Eintrag weg.</p>
      <p class="dlg-note">Er landet im Papierkorb der Datenbank, falls du ihn doch noch brauchst.</p>`,
    confirmText: 'Eintrag löschen',
    cancelText: 'Noch nicht'
  });
  if (!(res?.submit ?? res)) return;
  await vault.deleteEntry(id);
  return nachStrukturaenderung('Konto erledigt — Eintrag gelöscht.');
}

/**
 * Das Ergebnis des letzten Sicherheitschecks dieser Datenbank.
 *
 * Gespeichert wird nur, was sich nicht aus der Datei selbst ergibt: welche
 * Einträge in Leaks stehen, die E-Mail-Funde und der Zeitpunkt. Schwache
 * und mehrfach genutzte Passwörter rechnet der Kern beim Öffnen neu aus.
 * Ohne das stand nach jedem Neustart „noch nicht geprüft", und die Zahlen
 * der Lecks waren weg.
 */
export function restoreCheck() {
  const path = settings.get('database.current', null);
  const saved = path ? settings.forDatabase(path).securityCheck : null;
  if (!saved) return;
  state.lastCheck = saved.at ?? null;
  state.pwned = new Map(Object.entries(saved.pwned ?? {}));
  state.emailFindings = saved.emails ?? [];
}

async function storeCheck() {
  const path = settings.get('database.current', null);
  if (!path) return;
  const pwned = {};
  for (const [id, r] of state.pwned) if (r?.found) pwned[id] = { found: true, count: r.count };
  await settings.setForDatabase(path, 'securityCheck', {
    at: state.lastCheck,
    pwned,
    emails: state.emailFindings.map(f => ({ email: f.email, breaches: f.breaches ?? [] }))
  }, { silent: true });
}

/** Was eine Prüfung gefunden hat — zum Vergleich mit der nächsten. */
function findingKeys() {
  const keys = new Set();
  for (const [id, r] of state.pwned) if (r?.found) keys.add(`pw:${id}`);
  for (const f of state.emailFindings) for (const b of f.breaches ?? []) keys.add(`mail:${f.email}:${b.name}`);
  return keys;
}

/**
 * Hinweis des Systems. Das Notification-Plugin setzt die Web-API auf die
 * Benachrichtigungen von Android, Windows, macOS und Linux um.
 */
export async function notify(title, body) {
  try {
    if (!('Notification' in window)) return;
    let permission = Notification.permission;
    if (permission !== 'granted') permission = await Notification.requestPermission();
    if (permission === 'granted') new Notification(title, { body });
  } catch { /* ohne Hinweis weiter */ }
}

export async function runSecurityCheck({ silent = false } = {}) {
  if (state.checkRunning) return;
  state.checkRunning = true;
  renderSecurity();

  const errors = [];
  const before = state.lastCheck ? findingKeys() : null;

  if (settings.get('checks.passwordBreach', true)) {
    // Der Kern liefert nur Hashes; nach außen geht davon bloß das Präfix.
    for (const target of await vault.hashTargets()) {
      const r = await checkPwnedByHash(target);
      if (r.error) errors.push(`Passwort-Check: ${r.error}`);
      state.pwned.set(target.id, r);
    }
  } else state.pwned.clear();

  state.reused = settings.get('checks.reuseDetection', true)
    ? await vault.reusedIds() : new Set();

  state.strength = settings.get('checks.passwordStrength', true)
    ? await vault.strengthMap() : new Map();

  if (settings.get('checks.emailBreach', true)) {
    const configured = [];
    const addresses = configured.length ? configured : vault.collectEmails();
    const previous = new Map(state.emailFindings.map(f => [f.email, f]));
    state.emailFindings = [];
    for (const mail of addresses) {
      const r = await checkEmailBreached(mail);
      if (r.error) {
        errors.push(`E-Mail-Check: ${r.error}`);
        // Dienst gerade nicht erreichbar: den letzten Stand behalten, statt
        // die Adresse plötzlich als sauber zu zeigen.
        if (previous.has(mail)) { state.emailFindings.push(previous.get(mail)); continue; }
      }
      if (r.breaches.length) {
        const details = await breachAnalytics(mail);
        r.breaches = r.breaches.map(b => ({ ...b, ...(details.get(b.name) ?? {}) }));
      }
      state.emailFindings.push(r);
    }
  } else state.emailFindings = [];

  state.lastCheck = Date.now();
  await settings.set('checks.lastRunAt', state.lastCheck, { silent: true });
  await storeCheck();
  state.checkRunning = false;

  // Neues seit der letzten Prüfung? Dann Bescheid geben — gerade bei der
  // automatischen, die ohne Zutun im Hintergrund läuft.
  if (before && settings.get('checks.notify', true)) {
    const fresh = [...findingKeys()].filter(k => !before.has(k));
    const pw = fresh.filter(k => k.startsWith('pw:')).length;
    const mail = fresh.length - pw;
    if (fresh.length) {
      notify('WKeePass: neue Funde im Sicherheitscheck', [
        pw ? `${pw} ${pw === 1 ? 'Passwort steht' : 'Passwörter stehen'} neu in einem Leak.` : '',
        mail ? `${mail} ${mail === 1 ? 'neues Datenleck' : 'neue Datenlecks'} bei deinen E-Mail-Adressen.` : ''
      ].filter(Boolean).join(' '));
    }
  }
  renderSecurity();
  zeichne('übersicht');
  zeichne('einträge');

  if (!silent) {
    if (errors.length) banner(`Prüfung teilweise fehlgeschlagen: ${[...new Set(errors)][0]}`, 'warning', 6000);
    else {
      const n = countProblems();
      banner(n ? `${n} Funde in der Prüfung.` : 'Keine Probleme gefunden.', n ? 'warning' : 'success');
    }
  }
}
