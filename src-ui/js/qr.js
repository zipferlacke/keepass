/**
 * qr.js — QR-Codes lesen und erzeugen.
 *
 * Die Bilderfassung passiert im Webview (getUserMedia + Canvas), die
 * Dekodierung im Kern (ZXing über rxing, dann rqrr). Das ist der
 * einzige Weg, der überall funktioniert — die native BarcodeDetector-API
 * fehlt genau dort, wo die App läuft: in WebKitGTK und in Firefox.
 *
 * Ohne Kern gibt es folglich keinen Scanner; die Oberfläche meldet das.
 */

import { isTauri, isMobile, invoke } from './platform.js';
import { renderQrCode } from './ui.js';

const SCAN_INTERVAL_MS = 60;  // Pause zwischen zwei Prüfungen; die Prüfung selbst dauert länger

/** Kann in dieser Umgebung überhaupt gescannt werden? */
export function scannerAvailable() {
  return isTauri;
}

/* =========================================================
   Dekodierung
   ========================================================= */

/** Dekodiert ein Bild aus Rohbytes (PNG/JPEG). */
async function decodeBytes(bytes) {
  const result = await invoke('decode_qr_bytes', { bytes: Array.from(bytes) });
  return result || null;
}

/**
 * Kantenlänge, auf die ein Ausschnitt höchstens verkleinert wird. Nicht
 * kleiner: Ein TOTP-Code (otpauth://… mit Secret und Aussteller) hat
 * doppelt so viele Module wie ein Link. Bei zu wenigen Pixeln je Modul
 * erkennt rqrr den Link noch, den TOTP-Code nicht mehr.
 */
const SCAN_EDGE = 900;

/**
 * Welcher Anteil der kürzeren Bildseite je Durchgang geprüft wird. Der
 * Sucherrahmen deckt 75 % ab; enger (50 %) holt einen kleinen Code näher
 * heran, `1` ist das ganze Bild für den, der nicht mittig hält.
 */
const CROPS = [0.75, 0.5, 0.75, 1];

/** Ein Canvas für alle Bilder — neu anlegen kostet bei 10 Bildern je Sekunde. */
let scanCanvas = null;

/**
 * Prüft ein Kamerabild auf einen QR-Code.
 *
 * Schnell, weil ohne Umwege: Graustufen direkt aus dem Canvas, als rohe
 * Bytes an Rust — kein JPEG kodieren und wieder entpacken, keine JSON-Liste
 * mit Hunderttausenden Zahlen. Das war der Grund, warum das Erkennen früher
 * Sekunden dauerte.
 *
 * `center`: nur das mittlere Quadrat, dort wo der Sucherrahmen hinzeigt —
 * kleiner, also schneller, und der Code füllt es besser aus. Sonst das
 * ganze Bild, falls jemand nicht mittig hält.
 */
async function decodeFrame(video, crop, edge = SCAN_EDGE) {
  const vw = video.videoWidth ?? video.width;
  const vh = video.videoHeight ?? video.height;
  const center = crop < 1;
  const side = Math.min(vw, vh) * crop;
  const sx = center ? (vw - side) / 2 : 0;
  const sy = center ? (vh - side) / 2 : 0;
  const sw = center ? side : vw;
  const sh = center ? side : vh;

  const scale = Math.min(1, edge / Math.max(sw, sh));
  const w = Math.max(1, Math.round(sw * scale));
  const h = Math.max(1, Math.round(sh * scale));

  scanCanvas ??= document.createElement('canvas');
  scanCanvas.width = w;
  scanCanvas.height = h;
  const ctx = scanCanvas.getContext('2d', { willReadFrequently: true });
  ctx.drawImage(video, sx, sy, sw, sh, 0, 0, w, h);

  const rgba = ctx.getImageData(0, 0, w, h).data;
  const gray = new Uint8Array(w * h);
  for (let i = 0, j = 0; j < gray.length; i += 4, j++) {
    gray[j] = (rgba[i] * 77 + rgba[i + 1] * 150 + rgba[i + 2] * 29) >> 8;
  }

  const result = isMobile
    ? await invoke('decode_qr_gray', { width: w, data: toBase64(gray) })
    : await invoke('decode_qr_gray', gray, { headers: { 'x-width': String(w) } });
  return result || null;
}

/**
 * Bytes als Base64 — für Android, wo die Brücke nur JSON durchlässt.
 * In Blöcken, weil `String.fromCharCode(...bytes)` bei großen Bildern
 * den Stapel sprengt.
 */
function toBase64(bytes) {
  let text = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    text += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(text);
}

/* =========================================================
   Bilddatei scannen
   ========================================================= */

export async function scanFile(file) {
  if (!scannerAvailable()) throw new Error('Diese Umgebung kann keine QR-Codes lesen.');

  const bytes = new Uint8Array(await file.arrayBuffer());
  const value = await decodeBytes(bytes);
  if (!value) throw new Error('Kein QR-Code im Bild gefunden.');
  return value;
}

/**
 * Ein Foto (etwa frisch aus der Kamera-App) nach einem Code absuchen.
 *
 * Das Foto ist scharf gestellt und hoch aufgelöst — der sichere Weg, wenn
 * die Vorschau einen dichten Code nicht packt. Verkleinert wird hier im
 * Webview; das volle Bild als Zahlenliste an den Kern zu schicken, dauerte
 * auf dem Telefon Sekunden.
 */
export async function scanPhoto(file) {
  if (!scannerAvailable()) throw new Error('Diese Umgebung kann keine QR-Codes lesen.');
  const bitmap = await createImageBitmap(file);
  try {
    for (const crop of [1, 0.6]) {
      const value = await decodeFrame(bitmap, crop, 1600);
      if (value) return value;
    }
  } finally {
    bitmap.close?.();
  }
  throw new Error('Kein QR-Code im Foto gefunden.');
}

/* =========================================================
   Kamera scannen
   ========================================================= */

/**
 * @param {HTMLVideoElement} video Vorschau-Element
 * @returns {{promise: Promise<string>, stop: () => void}}
 */
/**
 * Wie die Kamera angefragt wird — der Reihe nach, bis eine Fassung Bilder
 * liefert.
 *
 * `facingMode: 'environment'` meint die **rückwärtige** Kamera. An einem
 * Rechner gibt es die nicht, und zusammen mit einer Wunschbreite, die zu
 * keiner angebotenen Auflösung passt, kommt die Aushandlung ins Straucheln —
 * eine eingebaute Kamera bietet oft nur ein einziges Format an, unter Linux
 * gern auch hochkant und als DMABuf.
 *
 * Deshalb zuerst ohne jede Vorgabe fragen: Dann sucht der Webview selbst das
 * aus, was das Gerät wirklich kann. Der Wunsch nach der rückwärtigen Kamera
 * kommt danach — auf einem Telefon ist er richtig, dort greift er dann.
 */
const DESKTOP_ATTEMPTS = [
  { label: 'Standardkamera', constraints: { video: true, audio: false } },
  { label: 'rückwärtige Kamera', constraints: { video: { facingMode: 'environment' }, audio: false } },
  // Anderes Format erzwingen — manche Treiber liefern nur im Standardformat Schwarz.
  { label: 'Kamera 640×480', constraints: { video: { width: { exact: 640 }, height: { exact: 480 } }, audio: false } }
];

/**
 * Auf dem Telefon umgekehrt: Dort ist die „Standardkamera" des Webviews
 * die vordere — und mit der fotografiert niemand einen QR-Code auf dem
 * Bildschirm. Also zuerst ausdrücklich die rückwärtige.
 */
const MOBILE_ATTEMPTS = [
  { label: 'rückwärtige Kamera (HD)', constraints: { video: { facingMode: { exact: 'environment' }, width: { ideal: 1920 }, height: { ideal: 1080 } }, audio: false } },
  { label: 'rückwärtige Kamera', constraints: { video: { facingMode: { exact: 'environment' } }, audio: false } },
  { label: 'rückwärtige Kamera (Wunsch)', constraints: { video: { facingMode: 'environment' }, audio: false } },
  { label: 'Standardkamera', constraints: { video: true, audio: false } }
];

const CAMERA_ATTEMPTS = isMobile ? MOBILE_ATTEMPTS : DESKTOP_ATTEMPTS;

/** So lange wird auf das erste Bild gewartet, bevor der nächste Versuch kommt. */
const FIRST_FRAME_TIMEOUT_MS = 4000;

/** Wartet, bis das Video Maße hat — vorher gibt es nichts zu lesen. */
function waitForFrames(video, timeout) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + timeout;

    const check = () => {
      if (video.videoWidth && video.videoHeight) return resolve();
      if (Date.now() > deadline) {
        return reject(new Error('Die Kamera liefert kein Bild.'));
      }
      setTimeout(check, 120);
    };
    check();
  });
}

/**
 * Kommt wirklich ein Bild, oder nur Schwarz? Manche Kameras (etwa unter
 * Linux, wenn der Treiber das Format nicht umsetzt) liefern Bilder mit
 * Maßen, aber ohne Inhalt. Bis zu 2,5 s wird gewartet — die ersten Bilder
 * sind oft dunkel, bis die Belichtung steht.
 */
async function hasPicture(video) {
  const canvas = document.createElement('canvas');
  canvas.width = 32;
  canvas.height = 32;
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  const deadline = Date.now() + 2500;
  while (Date.now() < deadline) {
    ctx.drawImage(video, 0, 0, 32, 32);
    const px = ctx.getImageData(0, 0, 32, 32).data;
    let max = 0;
    for (let i = 0; i < px.length; i += 4) max = Math.max(max, px[i], px[i + 1], px[i + 2]);
    if (max > 24) return true;
    await new Promise(r => setTimeout(r, 150));
  }
  return false;
}

/**
 * Dauerfokus einschalten, wo die Kamera ihn kann. Ohne ihn bleibt die
 * Rückkamera eines Telefons oft auf „unendlich" stehen — ein Code eine
 * Handbreit vor der Linse ist dann nie scharf genug.
 */
async function autofocus(stream) {
  const track = stream.getVideoTracks()[0];
  const modes = track?.getCapabilities?.().focusMode ?? [];
  if (!modes.includes('continuous')) return;
  try {
    await track.applyConstraints({ advanced: [{ focusMode: 'continuous' }] });
  } catch { /* dann eben mit dem, was die Kamera von sich aus macht */ }
}

export async function scanCamera(video) {
  if (!scannerAvailable()) throw new Error('Diese Umgebung kann keine QR-Codes lesen.');
  if (!navigator.mediaDevices?.getUserMedia) throw new Error('Kein Kamerazugriff möglich.');

  video.setAttribute('playsinline', '');
  video.muted = true;

  let stream = null;
  const problems = [];

  for (const attempt of CAMERA_ATTEMPTS) {
    let candidate = null;
    try {
      candidate = await navigator.mediaDevices.getUserMedia(attempt.constraints);
      video.srcObject = candidate;
      await video.play();
      await waitForFrames(video, FIRST_FRAME_TIMEOUT_MS);
      if (!await hasPicture(video)) throw new Error('liefert nur ein schwarzes Bild');

      stream = candidate;
      break;
    } catch (err) {
      problems.push(`${attempt.label}: ${err.message}`);
      candidate?.getTracks().forEach(t => t.stop());
      video.srcObject = null;
    }
  }

  // Ohne Bild lieber laut scheitern als eine schwarze Fläche zeigen: Sonst
  // sitzt man davor und weiß nicht, ob es lädt oder nicht geht.
  if (!stream) {
    throw new Error(`Kein Kamerabild. ${problems.join(' — ')}. Stattdessen geht „QR-Code aus Bild“ mit einem Screenshot oder Foto.`);
  }

  await autofocus(stream);

  let stopped = false;
  let timer = null;

  const stop = () => {
    stopped = true;
    clearTimeout(timer);
    stream.getTracks().forEach(t => t.stop());
    video.srcObject = null;
  };

  let round = 0;
  let failures = 0;

  // Wo der Webview den Barcode-Leser des Systems anbietet (Android), liest
  // der direkt aus der Vorschau — schneller als jedes Bild zum Kern zu
  // schicken. Der Kern bleibt der Weg für alle anderen und als Rückfall.
  let detector = null;
  try {
    if ('BarcodeDetector' in window) detector = new window.BarcodeDetector({ formats: ['qr_code'] });
  } catch { detector = null; }

  const promise = new Promise((resolve, reject) => {
    const tick = async () => {
      if (stopped) return reject(new Error('abgebrochen'));

      try {
        if (detector && video.videoWidth) {
          try {
            const codes = await detector.detect(video);
            const hit = codes.find(c => c.rawValue)?.rawValue;
            if (hit) { stop(); return resolve(hit); }
          } catch { detector = null; }
        }
        if (video.videoWidth && video.videoHeight) {
          // Reihum verschiedene Ausschnitte, siehe CROPS.
          const value = await decodeFrame(video, CROPS[round++ % CROPS.length]);
          failures = 0;
          if (value) { stop(); return resolve(value); }
        }
      } catch (err) {
        // Einzelne Bilder dürfen scheitern. Scheitert aber jedes, kann der
        // Scanner nie etwas finden — dann laut werden statt ewig zu suchen.
        if (++failures >= 15) { stop(); return reject(new Error(`Auswertung fehlgeschlagen: ${err.message ?? err}`)); }
      }

      timer = setTimeout(tick, SCAN_INTERVAL_MS);
    };

    tick();
  });

  return { promise, stop };
}

/* =========================================================
   QR-Code erzeugen
   ========================================================= */

export async function renderQr(element, content, colors = {}) {
  element.dataset.content = content;
  await renderQrCode(element, colors);
}

/* =========================================================
   Gescannte Inhalte deuten
   ---------------------------------------------------------
   Was per QR-Code tatsächlich standardisiert ist:

     otpauth://           TOTP/HOTP, de-facto-Standard (Key-URI-Format)
     otpauth-migration:// Sammelexport aus Google Authenticator und
                          kompatiblen Apps — Base64 + Protocol Buffers
     WIFI:                WLAN-Zugangsdaten, von Android/iOS unterstützt
     http(s)://           schlicht eine Adresse

   Was es NICHT gibt: einen Standard, um Passwörter oder Passkeys per
   QR-Code zu übertragen. Die FIDO-Codes beim Anmelden (`FIDO:/…`) sind
   ein Verbindungsaufbau zwischen zwei Geräten, keine übertragbaren
   Zugangsdaten — daraus lässt sich kein Eintrag anlegen.
   ========================================================= */

const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(bytes) {
  let bits = '';
  for (const b of bytes) bits += b.toString(2).padStart(8, '0');
  let out = '';
  for (let i = 0; i < bits.length; i += 5) {
    out += B32_ALPHABET[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)];
  }
  return out;
}

/** Minimaler Protobuf-Leser — nur so viel, wie das Migrationsformat braucht. */
function readProtobuf(bytes) {
  const fields = [];
  let i = 0;

  const varint = () => {
    let value = 0, shift = 0;
    while (i < bytes.length) {
      const b = bytes[i++];
      value += (b & 0x7f) * 2 ** shift;
      if ((b & 0x80) === 0) break;
      shift += 7;
    }
    return value;
  };

  while (i < bytes.length) {
    const key = varint();
    const field = key >>> 3;
    const type = key & 7;

    if (type === 0) fields.push({ field, value: varint() });
    else if (type === 2) {
      const len = varint();
      fields.push({ field, bytes: bytes.slice(i, i + len) });
      i += len;
    } else if (type === 5) i += 4;
    else if (type === 1) i += 8;
    else break;
  }
  return fields;
}

const ALGORITHMS = { 1: 'SHA1', 2: 'SHA256', 3: 'SHA512', 4: 'MD5' };
const DIGITS = { 1: 6, 2: 8 };

/** Zerlegt otpauth-migration://offline?data=… in einzelne Konten. */
export function parseMigration(uri) {
  const raw = new URL(uri).searchParams.get('data');
  if (!raw) throw new Error('Der Code enthält keine Daten.');

  const binary = atob(raw.replace(/-/g, '+').replace(/_/g, '/'));
  const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));

  const accounts = [];
  for (const entry of readProtobuf(bytes)) {
    if (entry.field !== 1 || !entry.bytes) continue;   // Feld 1: otp_parameters

    const params = readProtobuf(entry.bytes);
    const get = f => params.find(p => p.field === f);
    const str = f => {
      const p = get(f);
      return p?.bytes ? new TextDecoder().decode(p.bytes) : '';
    };

    const secretBytes = get(1)?.bytes;
    if (!secretBytes) continue;

    const label = str(2);
    const issuer = str(3) || (label.includes(':') ? label.split(':')[0] : '');
    const name = label.includes(':') ? label.split(':').slice(1).join(':') : label;

    accounts.push({
      secret: base32Encode(secretBytes),
      name: name.trim() || issuer || 'Konto',
      issuer: issuer.trim(),
      algorithm: ALGORITHMS[get(4)?.value] ?? 'SHA1',
      digits: DIGITS[get(5)?.value] ?? 6,
      period: 30,
      type: get(6)?.value === 1 ? 'hotp' : 'totp'
    });
  }

  if (!accounts.length) throw new Error('Im Code stecken keine lesbaren Konten.');
  return accounts;
}

/** WIFI:T:WPA;S:name;P:passwort;; */
function parseWifi(value) {
  const fields = {};
  for (const part of value.slice(5).split(';')) {
    const [key, ...rest] = part.split(':');
    if (key) fields[key.toUpperCase()] = rest.join(':');
  }
  return {
    name: fields.S ? `WLAN ${fields.S}` : 'WLAN',
    username: fields.S ?? '',
    password: fields.P ?? '',
    notes: fields.T ? `Verschlüsselung: ${fields.T}` : ''
  };
}

/**
 * Deutet einen gescannten Inhalt.
 * @returns {{kind: string, ...}} kind: totp | migration | wifi | url | text
 */
export function interpret(value) {
  const raw = String(value ?? '').trim();

  if (/^otpauth-migration:\/\//i.test(raw)) {
    return { kind: 'migration', accounts: parseMigration(raw) };
  }

  if (/^otpauth:\/\//i.test(raw)) {
    return { kind: 'totp', uri: raw };
  }

  if (/^WIFI:/i.test(raw)) {
    return { kind: 'wifi', ...parseWifi(raw) };
  }

  if (/^https?:\/\//i.test(raw)) {
    let host = raw;
    try { host = new URL(raw).hostname; } catch { /* Adresse unvollständig */ }
    return { kind: 'url', url: raw, name: host };
  }

  if (/^FIDO:\//i.test(raw)) {
    return { kind: 'fido' };
  }

  return { kind: 'text', text: raw };
}
