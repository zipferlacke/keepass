/**
 * platform.js — die einzige Tür zum Kern.
 *
 * Alles, was die Oberfläche vom Kern will, geht über `invoke()`. Läuft die
 * App in Tauri, landet der Aufruf in Rust. Läuft sie im reinen Browser,
 * beantwortet ihn `demo.js` aus `config/demo.json`.
 *
 * Deshalb gibt es oberhalb dieser Datei keine Fallunterscheidung mehr und
 * auch kein zweites Backend: Der Aufrufer sieht immer dieselbe
 * Schnittstelle, und der Unterschied steckt allein hier.
 */

export const isTauri = typeof window !== 'undefined' &&
  ('__TAURI_INTERNALS__' in window || '__TAURI__' in window);

/**
 * Läuft die App auf Android oder iOS? Dort gibt es manches nicht, was der
 * Desktop hat — allem voran die Browser-Erweiterung.
 */
export const isMobile = isTauri && /Android|iPhone|iPad/i.test(navigator.userAgent);

let cachedInvoke = null;
let demoModule = null;

async function resolveInvoke() {
  if (cachedInvoke) return cachedInvoke;

  // Variante 1: globales Objekt (withGlobalTauri = true)
  const globalInvoke = window.__TAURI__?.core?.invoke ?? window.__TAURI__?.invoke;
  if (typeof globalInvoke === 'function') {
    cachedInvoke = globalInvoke;
    return cachedInvoke;
  }

  // Variante 2: gebündeltes API-Paket
  const specifier = '@tauri-apps/api/core';
  const mod = await import(/* @vite-ignore */ specifier);
  cachedInvoke = mod.invoke;
  return cachedInvoke;
}

async function resolveDemo() {
  demoModule ??= await import('../data/demo.js');
  return demoModule;
}

/* =========================================================
   Die Ladeanzeige
   ---------------------------------------------------------
   Speichern heißt Argon2: Der Kern rechnet absichtlich lange und hält
   dabei die Datenbank. Die Oberfläche kann in dieser Zeit nichts tun —
   bisher sah das aus, als hinge sie. Jetzt legt sich der Schleier aus
   wuefl-libs darüber (`.loading[data-loading]`, dieselbe Animation wie in
   MusicTrack), und man sieht: Es arbeitet.

   Zwei Vorkehrungen gegen Zappeln:
     * Erst nach VERZOEGERUNG zeigen — was schnell geht, bleibt unsichtbar.
     * Einmal gezeigt, mindestens MINDESTENS stehen lassen.
   ========================================================= */

/** Was im Hintergrund läuft oder ohnehin nur Millisekunden dauert. */
const OHNE_ANZEIGE = new Set([
  'vault_totp', 'vault_touch', 'vault_mark_accessed', 'vault_list_entries',
  'vault_folders', 'vault_strength', 'vault_hash_prefix', 'vault_duplicate_groups',
  'vault_reveal_secret', 'vault_copy_secret', 'vault_new_secret', 'vault_set_secret',
  'vault_drop_secret', 'vault_attachment', 'vault_fetch_icons', 'vault_security',
  'settings_read', 'settings_write', 'path_label', 'open_link', 'startup_database',
  'unlock_methods', 'browser_identified', 'fetch_page_title',
  'android_setup_status', 'android_setup_open',
  // Die Zusammenfassungen der Versionen laden im Hintergrund nach; die
  // Liste zeigt dafür schon „…". Ein Schleier sperrte sie währenddessen.
  'vault_version_step',
  'plugin:app|version', 'database_modified',
  // Die Auswahlfenster des Systems stehen offen, solange der Nutzer sucht.
  'pick_database_file', 'pick_save_path', 'pick_attachments', 'save_attachment',
  'decode_qr_gray', 'decode_qr_bytes',
]);

const VERZOEGERUNG = 300;
const MINDESTENS = 400;

let laufend = 0;
let zeiger = null;
let seit = 0;

function koerper() {
  return typeof document === 'undefined' ? null : document.body;
}

function anzeigen() {
  seit = Date.now();
  koerper()?.setAttribute('data-loading', '');
}

function beginnt(command) {
  if (OHNE_ANZEIGE.has(command)) return false;
  if (++laufend === 1) zeiger = setTimeout(anzeigen, VERZOEGERUNG);
  return true;
}

function endet() {
  if (--laufend > 0) return;
  clearTimeout(zeiger);
  zeiger = null;

  // Kurz vor Schluss aufgetaucht? Dann einen Moment stehen lassen, sonst
  // blitzt der Schleier nur auf.
  //
  // Weggenommen wird immer, wenn nichts mehr läuft — auch wenn dieser
  // Aufruf selbst nie zu sehen war. Vorher kehrte die Funktion dann früh
  // zurück, und es gab einen Wettlauf: Ein langsamer Aufruf zeigt den
  // Schleier, endet, das Wegnehmen wartet die Mindestzeit ab; in der
  // startet ein schneller, das Wegnehmen sieht „läuft noch" und lässt es,
  // der schnelle endet ungesehen — und der Schleier stand für immer. So
  // geschehen beim Schließen der Versionen.
  const rest = seit ? Math.max(0, MINDESTENS - (Date.now() - seit)) : 0;
  seit = 0;
  setTimeout(() => {
    if (laufend === 0) koerper()?.removeAttribute('data-loading');
  }, rest);
}

/**
 * Ruft ein Kommando des Kerns auf.
 *
 * Fehler werden durchgereicht, nicht verschluckt — der Aufrufer soll
 * merken, wenn etwas nicht geht, statt stillschweigend mit `null`
 * weiterzurechnen.
 *
 * Dauert es, kommt die Ladeanzeige — siehe oben.
 */
export async function invoke(command, args = {}, options = undefined) {
  const zeigt = beginnt(command);
  try {
    if (isTauri) {
      const fn = await resolveInvoke();
      // `options` für Rohdaten mit Kopfzeilen (siehe qr.js) — sonst leer.
      return await (options ? fn(command, args, options) : fn(command, args));
    }

    const demo = await resolveDemo();
    return await demo.runCommand(command, args);
  } catch (cause) {
    // Rust gibt Fehler als schlichte Zeichenkette zurück, und `invoke`
    // weist das Promise damit zurück — nicht mit einem `Error`. Wer dann
    // `err.message` liest, bekommt `undefined` zu sehen. Deshalb hier
    // einmal zentral einpacken, statt an dreißig Stellen zu prüfen.
    throw asError(cause, command);
  } finally {
    if (zeigt) endet();
  }
}

function asError(cause, command) {
  if (cause instanceof Error) return cause;
  if (typeof cause === 'string' && cause) return new Error(cause);

  // Manche Fehler kommen als Objekt herüber, etwa aus den Plugins.
  const text = cause?.message ?? cause?.error ?? null;
  if (typeof text === 'string' && text) return new Error(text);

  return new Error(`Der Kern meldet einen Fehler bei „${command}“: ${JSON.stringify(cause)}`);
}

/* =========================================================
   Fähigkeiten der Umgebung
   ========================================================= */

/**
 * Welche Wege zum Entsperren gibt es auf diesem Gerät?
 *
 * Die Oberfläche entscheidet damit nur, welche Knöpfe sie anbietet. Was
 * hinter einem Weg passiert — Systemdialog, Siegel öffnen, Schlüssel
 * ableiten — bleibt vollständig im Kern.
 */
export function unlockMethods(path = null) {
  return invoke('unlock_methods', { path });
}

/** Öffnet den Dateiauswahldialog des Betriebssystems. */
export function pickDatabaseFile() {
  return invoke('pick_database_file');
}

/** Fragt, wohin eine neue Datenbank geschrieben werden soll. */
export function pickSavePath(suggested = 'passwoerter.kdbx') {
  return invoke('pick_save_path', { suggested });
}

/**
 * Horcht auf ein Ereignis des Kerns — etwa `vault-locked`, wenn die
 * Selbstsperre zugeschlagen hat.
 *
 * Ohne Tauri gibt es keine Ereignisse; dann passiert schlicht nichts.
 */
export async function listen(event, handler) {
  if (!isTauri) return () => {};

  const listener = window.__TAURI__?.event?.listen;
  if (typeof listener === 'function') return listener(event, handler);

  const specifier = '@tauri-apps/api/event';
  const mod = await import(/* @vite-ignore */ specifier);
  return mod.listen(event, handler);
}
