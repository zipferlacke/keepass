/**
 * security.js
 * ---------------------------------------------------------------
 * 1. Passwortstärke  — komplett lokal, keine Netzanfrage
 * 2. Passwort-Leak   — HIBP "Pwned Passwords" per k-Anonymity
 *                      (nur die ersten 5 Hex-Zeichen des SHA-1 gehen raus)
 * 3. E-Mail-Leak     — XposedOrNot, kostenlos und ohne API-Key
 *
 * Beide Netz-Checks laufen nur, wenn sie in den Einstellungen
 * aktiviert sind. Der Aufrufer prüft das (siehe app.js).
 */

/* =========================================================
   1. Passwortstärke
   ========================================================= */

const COMMON = new Set([
  'passwort', 'password', 'passwort1', '123456', '12345678', '123456789', 'qwertz',
  'qwerty', 'hallo', 'admin', 'letmein', 'welcome', 'monkey', 'dragon', 'iloveyou',
  'sonnenschein', 'fussball', 'schatz', 'ficken', 'arschloch', 'daniel', 'master'
]);

const SEQUENCES = ['abcdefghijklmnopqrstuvwxyz', '01234567890', 'qwertzuiopasdfghjklyxcvbnm', 'qwertyuiopasdfghjklzxcvbnm'];

/**
 * @returns {{score:0|1|2|3|4, entropy:number, label:string, hints:string[]}}
 */
export function passwordStrength(pw) {
  const hints = [];
  if (!pw) return { score: 0, entropy: 0, label: 'leer', hints: ['Kein Passwort gesetzt.'] };

  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 33;

  let entropy = pw.length * Math.log2(pool || 1);

  // Abzüge für Muster
  const lower = pw.toLowerCase();

  if (COMMON.has(lower)) { entropy -= 40; hints.push('Steht auf Listen häufiger Passwörter.'); }
  for (const w of COMMON) {
    if (w.length >= 5 && lower.includes(w)) {
      // Je mehr des Passworts aus dem bekannten Wort besteht, desto stärker der Abzug.
      const share = w.length / pw.length;
      entropy -= 14 + Math.round(share * 34);
      hints.push(`Enthält das gängige Wort „${w}“.`);
      break;
    }
  }

  if (/^(.)\1+$/.test(pw)) { entropy -= 25; hints.push('Besteht nur aus einem wiederholten Zeichen.'); }
  if (/(.)\1{2,}/.test(pw)) { entropy -= 8; hints.push('Enthält mehrfach wiederholte Zeichen.'); }

  for (const seq of SEQUENCES) {
    for (let i = 0; i + 4 <= seq.length; i++) {
      const part = seq.slice(i, i + 4);
      if (lower.includes(part) || lower.includes([...part].reverse().join(''))) {
        entropy -= 12;
        hints.push('Enthält eine Tastatur- oder Alphabet-Reihenfolge.');
        i = seq.length;
        break;
      }
    }
  }

  if (/^\d+$/.test(pw)) { entropy -= 12; hints.push('Besteht nur aus Ziffern.'); }
  if (/^(19|20)\d{2}$/.test(pw)) { entropy -= 10; hints.push('Sieht aus wie eine Jahreszahl.'); }

  if (pw.length < 8) hints.push('Kürzer als 8 Zeichen.');
  if (!/[A-Z]/.test(pw)) hints.push('Keine Großbuchstaben.');
  if (!/[^a-zA-Z0-9]/.test(pw)) hints.push('Keine Sonderzeichen.');

  entropy = Math.max(0, entropy);

  let score;
  if (entropy < 28) score = 0;
  else if (entropy < 40) score = 1;
  else if (entropy < 60) score = 2;
  else if (entropy < 80) score = 3;
  else score = 4;

  const labels = ['sehr schwach', 'schwach', 'mittel', 'stark', 'sehr stark'];
  return { score, entropy: Math.round(entropy), label: labels[score], hints: [...new Set(hints)] };
}

/* =========================================================
   2. Passwort-Leak-Check (HIBP, k-Anonymity)
   ---------------------------------------------------------
   Die Oberfläche bekommt vom Kern nur SHA-1-Präfix und -Suffix,
   nie das Passwort. Nach außen geht ausschließlich das Präfix.
   ========================================================= */

const rangeCache = new Map();

async function fetchRange(prefix) {
  if (rangeCache.has(prefix)) return rangeCache.get(prefix);

  const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
    headers: { 'Add-Padding': 'true' }
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);

  const map = new Map();
  for (const line of (await res.text()).split('\n')) {
    const [suffix, count] = line.trim().split(':');
    if (suffix) map.set(suffix.toUpperCase(), parseInt(count, 10) || 0);
  }
  rangeCache.set(prefix, map);
  return map;
}

/**
 * @param {{prefix: string, suffix: string}} hash Vom Kern geliefert
 * @returns {Promise<{found: boolean, count: number, error?: string}>}
 */
export async function checkPwnedByHash(hash) {
  if (!hash?.prefix || !hash?.suffix) return { found: false, count: 0 };
  try {
    const range = await fetchRange(hash.prefix.toUpperCase());
    const count = range.get(hash.suffix.toUpperCase()) ?? 0;
    return { found: count > 0, count };
  } catch (err) {
    return { found: false, count: 0, error: String(err.message || err) };
  }
}

/* =========================================================
   3. E-Mail-Leak-Check (XposedOrNot — kostenlos, kein API-Key)
   ========================================================= */

const mailCache = new Map();

/**
 * @returns {Promise<{email:string, breaches:Array<{name:string}>, error?:string}>}
 */
export async function checkEmailBreached(email) {
  if (!email || !email.includes('@')) return { email, breaches: [] };
  if (mailCache.has(email)) return mailCache.get(email);

  try {
    const res = await fetch(`https://api.xposedornot.com/v1/check-email/${encodeURIComponent(email)}`);

    if (res.status === 404) {
      const clean = { email, breaches: [] };
      mailCache.set(email, clean);
      return clean;
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}`);

    const data = await res.json();
    // API-Form: { breaches: [[ "Name1", "Name2", ... ]] }
    const names = Array.isArray(data?.breaches?.[0]) ? data.breaches[0] : [];
    const result = { email, breaches: names.map(n => ({ name: n })) };
    mailCache.set(email, result);
    return result;
  } catch (err) {
    return { email, breaches: [], error: String(err.message || err) };
  }
}

/** Zusatzdetails (Datum, betroffene Daten) zu einem Leak-Namen. */
export async function breachDetails(name) {
  try {
    const res = await fetch(`https://api.xposedornot.com/v1/breach-analytics?domain=${encodeURIComponent(name)}`);
    if (!res.ok) return null;
    return await res.json();
  } catch { return null; }
}

/* =========================================================
   Hinweis: Die Erkennung mehrfach genutzter Passwörter ist in den
   Kern gewandert (vault.reusedIds) — dort liegen die Werte, hier
   nicht mehr.
   ========================================================= */
