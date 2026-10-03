/**
 * pruef.js — die kleinste brauchbare Prüfhilfe.
 *
 * Ein Modultest sieht so aus:
 *
 *   import { pruefe, gleich, wahr, bericht } from '../lib/pruef.js';
 *   pruefe('zählt nur, was nicht im Papierkorb liegt', () => {
 *     gleich(liveEntries().length, 2);
 *   });
 *   bericht();
 *
 * Jede Prüfung meldet sich einzeln; am Ende steht eine Zeile mit der
 * Bilanz. Was schiefgeht, kommt als ERROR heraus — und damit scheitert
 * auch der Aufruf von `tests/lib/lauf.sh`.
 */
import { melde } from './melden.js';

const faelle = [];

export function pruefe(name, fn) {
  faelle.push({ name, fn });
}

export function gleich(ist, soll, was = '') {
  const a = JSON.stringify(ist);
  const b = JSON.stringify(soll);
  if (a !== b) throw new Error(`${was || 'Wert'}: ${a} statt ${b}`);
}

export function wahr(bedingung, was = '') {
  if (!bedingung) throw new Error(`${was || 'Bedingung'} ist nicht wahr`);
}

export async function wirft(fn, was = '') {
  try { await fn(); } catch { return; }
  throw new Error(`${was || 'Aufruf'} hätte scheitern müssen`);
}

/** Führt alle angemeldeten Fälle aus und zieht Bilanz. */
export async function bericht() {
  let gut = 0;
  for (const fall of faelle) {
    try {
      await fall.fn();
      melde('OK', fall.name);
      gut++;
    } catch (e) {
      melde('ERROR', `${fall.name}: ${e?.message ?? e}`);
    }
  }
  melde('BILANZ', `${gut} von ${faelle.length} Prüfungen gut`);
}
