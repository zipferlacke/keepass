/**
 * qr.js — QR-Codes lesen und erzeugen.
 *
 * Die Bilderfassung passiert im Webview (getUserMedia + Canvas), die
 * Dekodierung immer im Kern über `decode_qr_bytes` (rqrr). Das ist der
 * einzige Weg, der überall funktioniert — die native BarcodeDetector-API
 * fehlt genau dort, wo die App läuft: in WebKitGTK und in Firefox.
 *
 * Ohne Kern gibt es folglich keinen Scanner; die Oberfläche meldet das.
 */

import { isTauri, isMobile, invoke } from './platform.js';
import { renderQrCode } from './ui.js';

const MAX_EDGE = 800;        // Frames vor dem Senden herunterskalieren
const SCAN_INTERVAL_MS = 60;  // Pause zwischen zwei Prüfungen; die Prüfung selbst dauert länger

/** Kann in dieser Umgebung überhaupt gescannt werden? */
export function scannerAvailable() {
  return isTauri;
}

export async function cameraAvailable() {
  if (!navigator.mediaDevices?.getUserMedia) return false;
  try {
    const devices = await navigator.mediaDevices.enumerateDevices();
    return devices.some(d => d.kind === 'videoinput');
  } catch { return false; }
}

/* =========================================================
   Dekodierung
   ========================================================= */

/** Dekodiert ein Bild aus Rohbytes (PNG/JPEG). */
async function decodeBytes(bytes) {
  const result = await invoke('decode_qr_bytes', { bytes: Array.from(bytes) });
  return result || null;
}

/** Kantenlänge des Ausschnitts, der je Kamerabild geprüft wird. */
const SCAN_EDGE = 640;

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
async function decodeFrame(video, center) {
  const vw = video.videoWidth;
  const vh = video.videoHeight;
  const side = center ? Math.min(vw, vh) * 0.75 : Math.max(vw, vh);
  const sx = center ? (vw - side) / 2 : 0;
  const sy = center ? (vh - side) / 2 : 0;
  const sw = center ? side : vw;
  const sh = center ? side : vh;

  const scale = Math.min(1, SCAN_EDGE / Math.max(sw, sh));
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

  const result = await invoke('decode_qr_gray', gray, { headers: { 'x-width': String(w) } });
  return result || null;
}

/** Zeichnet eine Bildquelle skaliert auf ein Canvas und liefert JPEG-Bytes. */
async function sourceToBytes(source, width, height) {
  const scale = Math.min(1, MAX_EDGE / Math.max(width, height));
  const w = Math.max(1, Math.round(width * scale));
  const h = Math.max(1, Math.round(height * scale));

  const canvas = document.createElement('canvas');
  canvas.width = w;
  canvas.height = h;
  canvas.getContext('2d', { willReadFrequently: true }).drawImage(source, 0, 0, w, h);

  const blob = await new Promise(res => canvas.toBlob(res, 'image/jpeg', 0.8));
  if (!blob) throw new Error('Bild konnte nicht verarbeitet werden.');
  return new Uint8Array(await blob.arrayBuffer());
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
  { label: 'rückwärtige Kamera', constraints: { video: { facingMode: 'environment' }, audio: false } }
];

/**
 * Auf dem Telefon umgekehrt: Dort ist die „Standardkamera" des Webviews
 * die vordere — und mit der fotografiert niemand einen QR-Code auf dem
 * Bildschirm. Also zuerst ausdrücklich die rückwärtige.
 */
const MOBILE_ATTEMPTS = [
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
    throw new Error(`Kein Kamerabild. ${problems.join(' — ')}`);
  }

  let stopped = false;
  let timer = null;

  const stop = () => {
    stopped = true;
    clearTimeout(timer);
    stream.getTracks().forEach(t => t.stop());
    video.srcObject = null;
  };

  let round = 0;

  const promise = new Promise((resolve, reject) => {
    const tick = async () => {
      if (stopped) return reject(new Error('abgebrochen'));

      try {
        if (video.videoWidth && video.videoHeight) {
          // Meist die Mitte, jedes dritte Mal das ganze Bild.
          const value = await decodeFrame(video, ++round % 3 !== 0);
          if (value) { stop(); return resolve(value); }
        }
      } catch {
        // einzelne Frames dürfen fehlschlagen
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
