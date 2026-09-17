/**
 * demo.js — Ersatzkern für die Entwicklung ohne Rust.
 *
 * Läuft die Oberfläche nicht in Tauri, gibt es kein Backend. Dann springt
 * dieses Modul ein und beantwortet dieselben Kommandos, die sonst Rust
 * beantwortet — mit Daten aus `config/demo.json`.
 *
 * Wichtig: Es gibt genau eine Stelle, die zwischen echt und Demo
 * unterscheidet, und das ist `platform.js`. Alles darüber ruft
 * ausnahmslos `invoke()` auf und merkt vom Unterschied nichts.
 *
 * Für die App-Version ist dieses Modul bedeutungslos — dort wird es nie
 * geladen. Es darf deshalb ersatzlos verschwinden, sobald der Rust-Kern
 * vollständig ist.
 */

import { passwordStrength } from './security.js';
import { generateTotp, secondsRemaining } from './totp.js';

const DEMO_URL = './config/demo.json';

/* =========================================================
   Zustand
   ========================================================= */

let data = null;          // { database, folders, secrets, entries }
let loading = null;       // damit parallele Aufrufe nur einmal laden
let nextToken = 0;
let nextRef = 0;
const binaries = new Map();
let settingsMemory = null;
let demoPin = null;       // in der Demo nur im Speicher, kein Siegel
const demoAllowed = new Set();  // Pfade, die mit der PIN aufgehen dürfen

function ensureLoaded() {
  if (data) return Promise.resolve(data);

  loading ??= (async () => {
    const res = await fetch(DEMO_URL, { cache: 'no-store' });
    if (!res.ok) throw new Error(`Demo-Daten nicht lesbar (${res.status}).`);
    data = await res.json();

    // Beispielanhänge liegen in der Demo direkt in der JSON-Datei.
    for (const [ref, att] of Object.entries(data.attachments ?? {})) binaries.set(ref, att);

    // Höchsten vergebenen Token merken, damit neue nicht kollidieren
    for (const key of Object.keys(data.secrets)) {
      const n = Number(key.replace(/^s/, ''));
      if (Number.isFinite(n) && n > nextToken) nextToken = n;
    }
    return data;
  })();

  return loading;
}

const clone = value => structuredClone(value);

function nowIso() {
  return new Date().toISOString().replace(/\.\d+Z$/, 'Z');
}

function newToken() {
  return `s${++nextToken}`;
}

function newUuid() {
  return crypto.randomUUID();
}

/* =========================================================
   Ordner
   ========================================================= */

/** Legt einen Pfad samt aller Elternebenen an. */
function ensureFolder(path) {
  if (!path) return false;
  const parts = path.split('/').filter(Boolean);
  let changed = false;

  for (let i = 1; i <= parts.length; i++) {
    const sub = parts.slice(0, i).join('/');
    if (!data.folders.includes(sub)) { data.folders.push(sub); changed = true; }
  }
  return changed;
}

/** So heißt der Papierkorb, wenn die Datenbank noch keinen hat. */
const RECYCLE_BIN = 'Papierkorb';

const inRecycleBin = folder => folder === RECYCLE_BIN || folder.startsWith(`${RECYCLE_BIN}/`);

/** Alle Pfade, die unter `path` liegen — inklusive `path` selbst. */
function subtree(path) {
  return data.folders.filter(f => f === path || f.startsWith(`${path}/`));
}

/** Benennt einen Pfadanfang in allen Ordnern und Einträgen um. */
function repath(from, to) {
  data.folders = data.folders.map(f =>
    f === from ? to : f.startsWith(`${from}/`) ? to + f.slice(from.length) : f);

  for (const entry of data.entries) {
    if (entry.folder === from) entry.folder = to;
    else if (entry.folder.startsWith(`${from}/`)) entry.folder = to + entry.folder.slice(from.length);
  }
}

/** Setzt `moved` direkt vor oder hinter `reference` in einer Liste ein. */
function reorder(list, moved, reference, position) {
  const from = list.indexOf(moved);
  if (from === -1) return false;

  list.splice(from, 1);

  const at = list.indexOf(reference);
  if (at === -1) { list.splice(from, 0, moved); return false; }

  list.splice(position === 'after' ? at + 1 : at, 0, moved);
  return true;
}

/* =========================================================
   Einträge
   ========================================================= */

function findEntry(id) {
  return data.entries.find(e => e.id === id) ?? null;
}

function saveEntry(input) {
  const entry = {
    id: input.id ?? newUuid(),
    folder: input.folder || 'Allgemein',
    name: input.name ?? '',
    username: input.username ?? '',
    url: input.url ?? '',
    notes: input.notes ?? '',
    tags: input.tags ?? [],
    modified: nowIso(),
    accessed: nowIso(),
    hasPassword: Boolean(input.passwordToken),
    passwordToken: input.passwordToken ?? null,
    hasTotp: Boolean(input.totpToken),
    totpToken: input.totpToken ?? null,
    totpConfig: input.totpConfig ?? { digits: 6, period: 30, algorithm: 'SHA1' },
    passkey: Boolean(input.passkey),
    expires: input.expires ?? null,
    attachments: input.attachments ?? []
  };

  ensureFolder(entry.folder);

  const at = data.entries.findIndex(e => e.id === entry.id);
  if (at === -1) data.entries.push(entry);
  else data.entries[at] = entry;

  return entry;
}

/* =========================================================
   Kommandos — dieselben Namen wie in Rust
   ========================================================= */

const commands = {

  /* ---------- Entsperren ---------- */

  async unlock_methods({ path }) {
    // Im Browser gibt es weder Schlüsselbund noch Sensor.
    return {
      password: true,
      pinSet: demoPin !== null,
      pin: demoPin !== null && demoAllowed.has(path ?? ''),
      biometric: false,
      keyring: false,
      device: false,
      deviceAvailable: false,
      deviceLabel: null
    };
  },

  async vault_unlock({ path, method, secret, remember }) {
    if (method === 'biometric' || method === 'device') {
      throw new Error('Biometrisches Entsperren ist auf dieser Plattform nicht angebunden.');
    }
    if (method === 'pin' && secret !== demoPin) {
      throw new Error('PIN falsch.');
    }

    await ensureLoaded();
    if (remember?.allowPin) demoAllowed.add(path ?? '');
    return { ...clone(data.database), readOnly: false, format: 'KDBX 4.1' };
  },

  /** Im Browser gibt es keine Dateien — die Demo tut nur so. */
  async vault_create({ path, remember }) {
    await ensureLoaded();
    if (remember?.allowPin) demoAllowed.add(path ?? '');
    return { name: String(path).split(/[\\/]/).pop(), path, readOnly: false, format: 'KDBX 4.1' };
  },

  async app_pin_create({ pin }) {
    demoPin = pin;
    return true;
  },

  /** Nur gegen die alte PIN — eine Wiederherstellung gibt es nicht. */
  async app_pin_change({ old, new: next }) {
    if (old !== demoPin) throw new Error('PIN falsch.');
    demoPin = next;
    return true;
  },

  async app_pin_clear() {
    demoPin = null;
    demoAllowed.clear();
    return true;
  },

  async vault_remember({ pin, allowPin, allowBiometric }) {
    if (pin !== demoPin) throw new Error('PIN falsch.');
    if (allowBiometric) throw new Error('Ohne Schlüsselbund lässt sich der Fingerabdruck nicht absichern.');

    const path = data?.database?.path ?? '';
    if (allowPin) demoAllowed.add(path); else demoAllowed.delete(path);
    return true;
  },

  async vault_remember_device() {
    throw new Error('Einen Geräteschlüssel gibt es nur in der Anwendung.');
  },

  async vault_forget({ path }) {
    demoAllowed.delete(path);
    return true;
  },

  /** „Ich bin es" — im Browser nur über die PIN. */
  async confirm_presence({ method, secret }) {
    if (method === 'biometric') {
      throw new Error('Biometrisches Bestätigen ist auf dieser Plattform nicht angebunden.');
    }
    if (method === 'master') return true;   // die Demo kennt kein echtes
    if (secret !== demoPin) throw new Error('PIN falsch.');
    return true;
  },

  async browser_identified() { return true; },

  /* ---------- Datenbank ---------- */

  async vault_list_entries() {
    await ensureLoaded();
    return data.entries.map(e => ({ ...clone(e), recycled: inRecycleBin(e.folder) }));
  },

  async vault_folders() {
    await ensureLoaded();
    return clone(data.folders);
  },

  /** In der Demo wird nichts geschrieben — die Änderungen bleiben im Speicher. */
  async vault_commit() {
    return true;
  },

  async vault_lock() {
    data = null;
    loading = null;
    binaries.clear();
    nextToken = 0;
    return true;
  },

  /* ---------- Einträge ---------- */

  async vault_save_entry({ entry }) {
    await ensureLoaded();
    return clone(saveEntry(entry));
  },

  /** Erst in den Papierkorb, beim zweiten Mal endgültig — wie im Kern. */
  async vault_delete_entry({ id }) {
    await ensureLoaded();
    const at = data.entries.findIndex(e => e.id === id);
    if (at === -1) return false;

    const entry = data.entries[at];

    if (!inRecycleBin(entry.folder)) {
      ensureFolder(RECYCLE_BIN);
      entry.folder = RECYCLE_BIN;
      return true;
    }

    data.entries.splice(at, 1);
    delete data.secrets[entry.passwordToken];
    delete data.secrets[entry.totpToken];
    return true;
  },

  async vault_empty_recycle_bin() {
    await ensureLoaded();
    const doomed = data.entries.filter(e => inRecycleBin(e.folder));

    for (const entry of doomed) {
      delete data.secrets[entry.passwordToken];
      delete data.secrets[entry.totpToken];
    }
    data.entries = data.entries.filter(e => !inRecycleBin(e.folder));
    return doomed.length;
  },

  /* ---------- Selbstsperre ---------- */

  // Im Browser gibt es keinen Wächter-Thread; die Kommandos existieren nur,
  // damit die Oberfläche denselben Weg nimmt.
  async vault_touch() { return true; },
  async vault_set_auto_lock() { return true; },

  async vault_move_entry({ id, folder }) {
    await ensureLoaded();
    const entry = findEntry(id);
    if (!entry) return false;

    ensureFolder(folder);
    entry.folder = folder;
    entry.modified = nowIso();
    return true;
  },

  async vault_reorder_entry({ id, referenceId, position }) {
    await ensureLoaded();
    const entry = findEntry(id);
    const reference = findEntry(referenceId);
    if (!entry || !reference) return false;

    // Einsortieren heißt auch: den Ordner des Ziels übernehmen
    entry.folder = reference.folder;
    return reorder(data.entries, entry, reference, position);
  },

  /* ---------- Ordner ---------- */

  async vault_create_folder({ path }) {
    await ensureLoaded();
    return ensureFolder(path);
  },

  async vault_rename_folder({ path, name }) {
    await ensureLoaded();
    if (!data.folders.includes(path) || !name) return false;

    const parent = path.split('/').slice(0, -1).join('/');
    repath(path, parent ? `${parent}/${name}` : name);
    return true;
  },

  async vault_move_folder({ path, parent }) {
    await ensureLoaded();
    if (!data.folders.includes(path)) return false;
    if (parent === path || parent.startsWith(`${path}/`)) return false;   // nicht in sich selbst

    const name = path.split('/').pop();
    repath(path, parent ? `${parent}/${name}` : name);
    return true;
  },

  async vault_remove_folder({ path }) {
    await ensureLoaded();
    const affected = subtree(path);
    if (!affected.length) return false;

    for (const entry of data.entries) {
      if (affected.includes(entry.folder)) entry.folder = 'Allgemein';
    }
    data.folders = data.folders.filter(f => !affected.includes(f));
    return true;
  },

  async vault_reorder_folder({ path, referencePath, position }) {
    await ensureLoaded();
    return reorder(data.folders, path, referencePath, position);
  },

  /* ---------- Geheimnisse ---------- */

  async vault_new_secret({ value }) {
    await ensureLoaded();
    const token = newToken();
    data.secrets[token] = value;
    return token;
  },

  async vault_set_secret({ token, value }) {
    await ensureLoaded();
    data.secrets[token] = value;
    return true;
  },

  async vault_drop_secret({ token }) {
    await ensureLoaded();
    delete data.secrets[token];
    return true;
  },

  async vault_reveal_secret({ token }) {
    await ensureLoaded();
    return data.secrets[token] ?? '';
  },

  async vault_copy_secret({ token }) {
    await ensureLoaded();
    await navigator.clipboard.writeText(data.secrets[token] ?? '');
    return true;
  },

  /* ---------- Auswertungen ---------- */

  async vault_strength({ token }) {
    await ensureLoaded();
    return passwordStrength(data.secrets[token] ?? '');
  },

  async vault_hash_prefix({ token }) {
    await ensureLoaded();
    const value = data.secrets[token];
    if (!value) return null;

    const buf = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(value));
    const hash = [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    return { prefix: hash.slice(0, 5), suffix: hash.slice(5) };
  },

  async vault_duplicate_groups() {
    await ensureLoaded();
    const byValue = new Map();

    for (const [token, value] of Object.entries(data.secrets)) {
      if (!byValue.has(value)) byValue.set(value, []);
      byValue.get(value).push(token);
    }
    return [...byValue.values()].filter(group => group.length > 1);
  },

  async vault_totp({ token, config = {} }) {
    await ensureLoaded();
    const secret = data.secrets[token];
    if (!secret) return null;

    const period = config.period || 30;
    const at = config.at ?? Date.now();
    return {
      code: await generateTotp({ secret, ...config, at }),
      remaining: secondsRemaining(period, at)
    };
  },

  /* ---------- Anhänge ---------- */

  async vault_attachment({ ref }) {
    return binaries.get(String(ref)) ?? null;
  },

  /**
   * Im Kern öffnet das den Dateidialog des Betriebssystems. Ohne Kern gibt
   * es keinen — deshalb hier ein winziger erfundener Anhang, damit sich der
   * Ablauf trotzdem durchklicken lässt.
   */
  async pick_attachments() {
    const ref = `staged:${nextRef++}`;
    const name = `Notiz ${nextRef}.txt`;
    const data = `data:text/plain;base64,${btoa('Beispielanhang aus den Demodaten.')}`;

    binaries.set(ref, { name, type: 'text/plain', data });
    return [{ name, type: 'text/plain', size: 32, ref }];
  },

  /** Ein Anhang eines gespeicherten Eintrags, sofort geschrieben — wie im Kern. */
  async vault_write_attachment({ entryId, name, ref, previous }) {
    await ensureLoaded();
    const entry = data.entries.find(e => e.id === entryId);
    if (!entry) throw new Error('Eintrag nicht gefunden.');
    const source = binaries.get(String(ref));
    if (!source) throw new Error('Der Anhang ist nicht mehr da.');

    const list = entry.attachments ?? [];
    if (list.some(a => a.name === name) && previous !== name) {
      throw new Error(`„${name}“ gibt es in diesem Eintrag schon.`);
    }

    const next = `demo-w${nextRef++}`;
    const type = source.type;
    binaries.set(next, { ...source, name });
    if (String(ref).startsWith('staged:')) binaries.delete(String(ref));

    const size = Math.floor((source.data.split(',')[1] ?? '').length * 3 / 4);
    entry.attachments = [
      ...list.filter(a => a.name !== name && a.name !== previous),
      { name, type, size, ref: next }
    ];
    return next;
  },

  async stage_attachment_content({ name, content }) {
    const ref = `staged:${nextRef++}`;
    const bytes = new TextEncoder().encode(content);
    const type = /\.md$/i.test(name) ? 'text/markdown' : /\.html?$/i.test(name) ? 'text/html' : 'text/plain';
    let binary = '';
    bytes.forEach(b => { binary += String.fromCharCode(b); });
    binaries.set(ref, { name, type, data: `data:${type};base64,${btoa(binary)}` });
    return { name, type, size: bytes.length, ref };
  },

  /**
   * Im Kern öffnet das den Speichern-Dialog des Systems. Ohne Kern gibt es
   * keinen Dateizugriff — im Browser ist der Blob-Download aber der richtige
   * Weg, und dort funktioniert er auch (anders als im Webview).
   */
  async save_attachment({ ref }) {
    const att = binaries.get(String(ref));
    if (!att) throw new Error('Der Anhang ist nicht mehr da.');

    const a = document.createElement('a');
    a.href = att.data;
    a.download = att.name;
    a.click();
    return att.name;
  },

  /* ---------- Passkeys ---------- */

  async passkey_list() {
    await ensureLoaded();
    return data.entries.filter(e => e.passkey).map(e => ({
      credentialId: `demo-${e.id}`,
      rpId: e.url,
      userName: e.username,
      entryId: e.id
    }));
  },

  async passkey_create() {
    throw new Error('Passkeys anlegen geht nur in der Desktop- und App-Version.');
  },

  async passkey_assert() {
    throw new Error('Passkeys anmelden geht nur in der Desktop- und App-Version.');
  },

  async passkey_delete({ credentialId }) {
    await ensureLoaded();
    const entry = data.entries.find(e => `demo-${e.id}` === credentialId);
    if (entry) entry.passkey = false;
    return Boolean(entry);
  },

  /* ---------- Einstellungen ---------- */

  async settings_read() { return settingsMemory; },

  async settings_write({ json }) {
    settingsMemory = JSON.parse(json);
    return true;
  },

  /* ---------- System ---------- */

  async pick_save_path({ suggested }) {
    return `(Demo)/${suggested}`;
  },

  /* ---------- Browser-Erweiterung ---------- */

  /**
   * Ohne Kern gibt es keinen Kanal und keine Manifest-Dateien. Die Demo
   * zeigt den Abschnitt deshalb als „nicht verfügbar", statt so zu tun.
   */
  async browser_status() {
    return {
      listening: false,
      socket: '(kein Kern — nur mit der Anwendung verfügbar)',
      installed: [],
      available: [],
      associations: []
    };
  },

  async browser_install() { throw new Error('Nur in der Anwendung möglich.'); },
  async browser_uninstall() { throw new Error('Nur in der Anwendung möglich.'); },
  async browser_forget() { return false; },
  async browser_answer() { return false; },

  /** Im Browser gibt es keine Aufrufargumente. */
  async startup_database() {
    return null;
  },

  async pick_database_file() {
    await ensureLoaded();
    return data.database.path;
  },

  /** Fremde Seiten sperren den Abruf per CORS aus — im Browser also nichts. */
  async fetch_page_title() { return null; },

  /* ---------- QR ---------- */

  async decode_qr_bytes() { return null; },
  async decode_qr_rgba() { return null; },
  async decode_qr_path() { return null; }
};

/* =========================================================
   Einstiegspunkt für platform.js
   ========================================================= */

export function runCommand(command, args = {}) {
  const fn = commands[command];
  if (!fn) throw new Error(`Unbekanntes Kommando: ${command}`);
  return fn(args);
}
