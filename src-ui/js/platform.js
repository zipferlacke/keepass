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
  demoModule ??= await import('./demo.js');
  return demoModule;
}

/**
 * Ruft ein Kommando des Kerns auf.
 *
 * Fehler werden durchgereicht, nicht verschluckt — der Aufrufer soll
 * merken, wenn etwas nicht geht, statt stillschweigend mit `null`
 * weiterzurechnen.
 */
export async function invoke(command, args = {}, options = undefined) {
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
