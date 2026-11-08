/**
 * vault.js — die Grenze zwischen Oberfläche und Datenbankkern.
 *
 * Verantwortung:
 *   Kern     Container öffnen und schreiben, Ver- und Entschlüsselung,
 *            Verwahrung aller Geheimnisse, TOTP, Hashes, Passwortstärke,
 *            Aufbau von Ordnern und Einträgen
 *   Webview  Darstellung und Bedienung
 *
 * Das Modul enthält keine Datenbanklogik. Es reicht Kommandos an `invoke()`
 * weiter und hält das Ergebnis zwischen, damit die Oberfläche Ordner,
 * Schlagworte und Einträge ohne `await` lesen kann.
 *
 * Der Webview hält kein Passwort dauerhaft. Er erhält Metadaten und
 * Platzhalter-Token; Klartext gibt es nur auf Anfrage (`revealSecret`) für
 * die Dauer der Anzeige. `copySecret` legt den Wert direkt in die
 * Zwischenablage, ohne ihn in den Webview zu geben.
 */

import { invoke } from '../core/platform.js';

const PASSKEY_FOLDER = 'Passkeys';

/* =========================================================
   Zwischenspeicher
   ---------------------------------------------------------
   Nach jeder Änderung einmal frisch aus dem Kern holen. Damit bleibt der
   Kern die einzige Wahrheit, und die Oberfläche kommt trotzdem ohne
   `await` an Ordner und Einträge.
   ========================================================= */

let entriesCache = [];
let foldersCache = [];
let dirty = false;
let opened = false;

async function refresh() {
  [entriesCache, foldersCache] = await Promise.all([
    invoke('vault_list_entries'),
    invoke('vault_folders')
  ]);
}

/** Führt eine Änderung aus und zieht danach den Zwischenspeicher nach. */
async function mutate(command, args) {
  const result = await invoke(command, args);
  await refresh();
  dirty = true;
  return result;
}

/* =========================================================
   Öffnen und Sperren
   ========================================================= */

/**
 * Entsperrt und öffnet die Datenbank.
 *
 * `method` ist `'password'`, `'pin'`, `'biometric'` oder `'device'`;
 * `secret` ist das Master-Passwort bzw. die PIN und bleibt bei Biometrie und
 * Geräteschlüssel leer. Den Weg zum Master-Passwort wählt der Kern; es
 * gelangt nie in den Webview.
 */
export async function unlock({ path, method = 'password', secret = null, keyfile = null, autoLockMinutes = 0, remember = null }) {
  const info = await invoke('vault_unlock', { path, method, secret, keyfile, autoLockMinutes, remember });
  await refresh();
  dirty = false;
  opened = true;
  return info;
}

/**
 * Übernimmt eine Datenbank, die an anderer Stelle geöffnet wurde (etwa im
 * kleinen Browser-Fenster). Der Kern kennt sie dann bereits; dieses Modul
 * setzt `opened`, da `listEntries` sonst eine leere Liste liefert.
 */
export async function adopt() {
  await refresh();
  dirty = false;
  opened = true;
}

/** Legt eine neue, leere Datenbank an und öffnet sie gleich. */
export async function create({ path, password, name = null, level = null, autoLockMinutes = 0, remember = null }) {
  const info = await invoke('vault_create', { path, password, name, level, autoLockMinutes, remember });
  await refresh();
  dirty = false;
  opened = true;
  return info;
}

/* ---------- Die PIN des Programms ----------
   Eine PIN für alles. Pro Datenbank wird nur entschieden, ob sie damit
   aufgehen darf — siehe `remember`. */

export const createPin = pin => invoke('app_pin_create', { pin });
export const changePin = (oldPin, newPin) => invoke('app_pin_change', { old: oldPin, new: newPin });
export const clearPin = () => invoke('app_pin_clear');

/** Schaltet die offene Datenbank für PIN und/oder Fingerabdruck frei. */
export const remember = (pin, allowPin, allowBiometric) =>
  invoke('vault_remember', { pin, allowPin, allowBiometric });

/**
 * Schaltet die offene Datenbank für den Geräteschlüssel (Windows Hello)
 * frei oder nimmt das zurück. Braucht keine PIN — das Gerät fragt selbst.
 */
export const rememberDevice = enable => invoke('vault_remember_device', { enable });

/** Nimmt die Freigabe einer Datenbank zurück. */
export const forget = path => invoke('vault_forget', { path });

/**
 * „Ich bin es" bestätigen — mit PIN, Master-Passwort oder Fingerabdruck.
 *
 * Eine festgelegte PIN gilt hier immer; sie dient als Nachweis, nicht als
 * Schlüssel wie beim Entsperren.
 */
/** Setzt die Ruhezeit der Selbstsperre neu. `0` schaltet sie ab. */
export const setAutoLock = minutes => invoke('vault_set_auto_lock', { minutes });

/** Meldet dem Kern Aktivität, damit die Selbstsperre nicht auslöst. */
export const touch = () => invoke('vault_touch');

/** Leert den Papierkorb endgültig. */
export const emptyRecycleBin = () => mutate('vault_empty_recycle_bin');

export async function lock() {
  await invoke('vault_lock');
  entriesCache = [];
  foldersCache = [];
  dirty = false;
  opened = false;
}

/** Übergibt die Änderungen an den Kern, der verschlüsselt und schreibt. */
export async function commit() {
  if (!opened || !dirty) return false;
  await invoke('vault_commit');
  dirty = false;
  return true;
}

export function hasUnsavedChanges() { return dirty; }

/** Holt Änderungen, die ein anderes Gerät in die Datei geschrieben hat. */
export async function sync() {
  if (!opened) return false;
  const changed = await invoke('vault_sync');
  if (changed) await refresh();
  return changed;
}

/* =========================================================
   Versionen
   ---------------------------------------------------------
   Der Kern hebt die letzten Stände der Datei auf (versions.rs). Hier sind
   nur die drei Aufrufe dazu; zurückgeholt wird in den Arbeitsspeicher, das
   Schreiben macht wie immer `commit()`.
   ========================================================= */

/** Die aufgehobenen Stände, der jüngste zuerst. */
export const versions = () => invoke('vault_versions');

/** Was sich seit diesem Stand geändert hat. */
export const versionChanges = id => invoke('vault_version_changes', { id });

/** Was mit einem Stand dazukam — der Vergleich mit dem Stand davor. */
export const versionStep = id => invoke('vault_version_step', { id });

/**
 * Holt einen Stand zurück — `entries` nennt einzelne Einträge, ohne sie
 * kommt alles zurück. Danach ist die Datei noch nicht geschrieben.
 */
export async function versionRestore(id, entries = null) {
  const zahl = await invoke('vault_version_restore', { id, entries });
  await refresh();
  dirty = true;
  return zahl;
}

/* =========================================================
   Konflikte
   ---------------------------------------------------------
   Einträge, die beim Zusammenführen auf beiden Seiten verschieden geändert
   waren (konflikt.rs). Entscheiden ändert den Stand in der App; geschrieben
   wird wie immer mit `commit()`.
   ========================================================= */

export const conflicts = () => invoke('vault_conflicts');

/** `choice`: `hier` (Fassung der App) oder `extern` (aus der Datei). */
export const resolveConflict = (id, choice) => mutate('vault_conflict_resolve', { id, choice });

/** Name, Format und Stärke der Verschlüsselung der offenen Datenbank. */
export const security = () => invoke('vault_security');

/** Ändert Name und/oder Stufe und schreibt die Datei gleich zurück. */
export async function setSecurity({ name = null, level = null }) {
  await mutate('vault_set_security', { name, level });
  await commit();
  return true;
}

/* =========================================================
   Lesen
   ========================================================= */

export async function listEntries() {
  if (!opened) return [];
  await refresh();
  return structuredClone(entriesCache);
}

export function getEntry(id) {
  const found = entriesCache.find(e => e.id === id);
  return found ? structuredClone(found) : null;
}

export function folders() {
  return [...foldersCache].sort((a, b) => a.localeCompare(b, 'de'));
}

export function allTags() {
  return [...new Set(entriesCache.flatMap(e => e.tags ?? []))].sort((a, b) => a.localeCompare(b, 'de'));
}

export function collectEmails() {
  const set = new Set();
  for (const e of entriesCache) if (e.username?.includes('@')) set.add(e.username.toLowerCase());
  return [...set];
}

/* =========================================================
   Einträge ändern
   ========================================================= */

export function saveEntry(entry) {
  return mutate('vault_save_entry', { entry });
}

export async function deleteEntry(id) {
  const entry = getEntry(id);
  if (!entry) return false;

  const ok = await mutate('vault_delete_entry', { id });

  // Die Werte gehören zum Eintrag und werden mit ihm gelöscht.
  if (entry.passwordToken) await invoke('vault_drop_secret', { token: entry.passwordToken });
  if (entry.totpToken) await invoke('vault_drop_secret', { token: entry.totpToken });
  return ok;
}

export function moveEntry(id, folder) {
  return mutate('vault_move_entry', { id, folder });
}

/**
 * Sortiert einen Eintrag direkt vor oder hinter einen anderen ein und
 * übernimmt dabei dessen Ordner.
 */
export function reorderEntry(id, referenceId, position = 'before') {
  return mutate('vault_reorder_entry', { id, referenceId, position });
}

/* =========================================================
   Ordner
   ========================================================= */

export function createFolder(path) {
  return mutate('vault_create_folder', { path });
}

export function renameFolder(path, name) {
  return mutate('vault_rename_folder', { path, name });
}

export function moveFolder(path, parent) {
  return mutate('vault_move_folder', { path, parent });
}

export function removeFolder(path) {
  return mutate('vault_remove_folder', { path });
}

export function reorderFolder(path, referencePath, position = 'before') {
  return mutate('vault_reorder_folder', { path, referencePath, position });
}

/* =========================================================
   Passkeys
   ---------------------------------------------------------
   Angelegt wird ein Passkey nie hier, sondern von der Gegenstelle: auf dem
   Desktop über den Native-Messaging-Host der Browser-Erweiterung, auf
   Android über den CredentialProviderService. Die Oberfläche zeigt nur an,
   was vorhanden ist.
   ========================================================= */

/** Stellt sicher, dass es den Passkey-Ordner gibt. */
export async function ensurePasskeyFolder() {
  if (!opened || foldersCache.includes(PASSKEY_FOLDER)) return;
  await createFolder(PASSKEY_FOLDER);
}

/* =========================================================
   Geheimnisse
   ========================================================= */

export const revealSecret = token => token ? invoke('vault_reveal_secret', { token }) : Promise.resolve('');
export const copySecret = token => token ? invoke('vault_copy_secret', { token }) : Promise.resolve(false);

/** Ohne Token wird ein neuer angelegt, mit Token der vorhandene überschrieben. */
export function setSecret(token, value) {
  return token
    ? invoke('vault_set_secret', { token, value }).then(() => token)
    : invoke('vault_new_secret', { value });
}

/* =========================================================
   Auswertungen — der Kern rechnet, die Werte bleiben dort
   ========================================================= */

export async function strengthMap() {
  const out = new Map();
  for (const e of entriesCache) {
    if (e.passwordToken) out.set(e.id, await invoke('vault_strength', { token: e.passwordToken }));
  }
  return out;
}

/** Für den k-Anonymity-Abgleich: nur der Hash verlässt den Kern, nie das Passwort. */
export function hashFor(entry) {
  if (!entry?.passwordToken) return Promise.resolve(null);
  return invoke('vault_hash_prefix', { token: entry.passwordToken });
}

export async function hashTargets() {
  const out = [];
  for (const e of entriesCache) {
    if (!e.passwordToken) continue;
    const hash = await invoke('vault_hash_prefix', { token: e.passwordToken });
    if (hash) out.push({ id: e.id, ...hash });
  }
  return out;
}

/** Einträge, deren Passwort mehrfach verwendet wird. */
export async function reusedIds() {
  const groups = await invoke('vault_duplicate_groups');
  const tokenToId = new Map(entriesCache.filter(e => e.passwordToken).map(e => [e.passwordToken, e.id]));

  const ids = new Set();
  for (const group of groups) {
    for (const token of group) {
      const id = tokenToId.get(token);
      if (id) ids.add(id);
    }
  }
  return ids;
}

export function totpFor(entry, extra = {}) {
  if (!entry.totpToken) return Promise.resolve(null);
  return invoke('vault_totp', { token: entry.totpToken, config: { ...(entry.totpConfig ?? {}), ...extra } });
}

/* =========================================================
   Anhänge
   ========================================================= */

export const attachmentData = ref => invoke('vault_attachment', { ref });
export const pickAttachments = () => invoke('pick_attachments');
export const saveAttachment = ref => invoke('save_attachment', { ref });
/** Legt Text als Datei im Zwischenspeicher ab — neue Datei oder bearbeiteter Inhalt. */
export const stageContent = (name, content) => invoke('stage_attachment_content', { name, content });

/**
 * Schreibt einen Anhang eines gespeicherten Eintrags sofort in die Datei —
 * ohne „Speichern" im Eintrag. `ref` ist neuer Inhalt aus dem
 * Zwischenspeicher oder der vorhandene Anhang (Umbenennen), `previous` der
 * bisherige Name. Liefert die neue Kennung.
 */
export async function writeAttachment({ entryId, name, ref, previous = null }) {
  const next = await mutate('vault_write_attachment', { entryId, name, ref, previous });
  await commit();
  return next;
}

/* ---------- Browser-Erweiterung ---------- */

/** Zustand der Anbindung: Kanal, eingerichtete Browser, Verknüpfungen. */
export const browserStatus = () => invoke('browser_status');

/** Trägt uns bei allen eingerichteten Browsern ein. */
export const browserInstall = () => invoke('browser_install');

/** Nimmt den Eintrag zurück und stellt, wo möglich, KeePassXC wieder her. */
export const browserUninstall = () => invoke('browser_uninstall');

/** Löst die Verknüpfung eines Browsers. */
export const browserForget = name => invoke('browser_forget', { name });

// Anfragen beantwortet das kleine Fenster (js/request.js) über
// `browser_answer`.

/** Mit welcher Datei wurde die Anwendung aufgerufen? (Doppelklick auf .kdbx) */
export const startupDatabase = () => invoke('startup_database');

/** Vermerkt die Nutzung im Eintrag selbst (LastAccessTime) — für „Inaktive Einträge". */
export const markAccessed = (ids, persist = false) => invoke('vault_mark_accessed', { ids, persist });

/** Android: Stand von Autofill, Passkeys und Kamera; `null` auf anderen Systemen. */
export const androidSetupStatus = () => invoke('android_setup_status');

/** Android: in die passende Systemeinstellung springen. */
export const androidSetupOpen = what => invoke('android_setup_open', { what });

/** Öffnet eine Webadresse im Browser des Systems (nur http/https). */
export const openLink = url => invoke('open_link', { url });

/**
 * Website-Icons im Hintergrund holen und in der Datenbank ablegen.
 * `ids` null = alle, denen eines fehlt; `force` lädt auch vorhandene neu.
 */
export const fetchIcons = (ids = null, force = false) => invoke('vault_fetch_icons', { ids, force });
