/**
 * totp.js — RFC 6238 / RFC 4226 über WebCrypto.
 * Unterstützt SHA-1, SHA-256, SHA-512 und 6–8 Stellen.
 */

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Decode(input) {
  const clean = String(input).replace(/=+$/, '').replace(/\s+/g, '').toUpperCase();
  let bits = '';
  for (const c of clean) {
    const v = B32.indexOf(c);
    if (v === -1) continue;
    bits += v.toString(2).padStart(5, '0');
  }
  const out = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return new Uint8Array(out);
}

const HASHES = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' };

export async function generateTotp({ secret, period = 30, digits = 6, algorithm = 'SHA1', at = Date.now() }) {
  const key = base32Decode(secret);
  if (!key.length) return '─'.repeat(digits);

  const counter = Math.floor(at / 1000 / period);
  const msg = new ArrayBuffer(8);
  const dv = new DataView(msg);
  dv.setUint32(0, Math.floor(counter / 2 ** 32));
  dv.setUint32(4, counter >>> 0);

  const hash = HASHES[String(algorithm).toUpperCase()] ?? 'SHA-1';
  const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash }, false, ['sign']);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, msg));

  const offset = sig[sig.length - 1] & 0x0f;
  const bin =
    ((sig[offset] & 0x7f) << 24) |
    ((sig[offset + 1] & 0xff) << 16) |
    ((sig[offset + 2] & 0xff) << 8) |
    (sig[offset + 3] & 0xff);

  return String(bin % 10 ** digits).padStart(digits, '0');
}

/** Sekunden bis zum Ablauf des aktuellen Codes. */
export function secondsRemaining(period = 30, at = Date.now()) {
  return period - Math.floor(at / 1000) % period;
}

/** Parst otpauth://totp/... URIs (QR-Code-Import). */
export function parseOtpauth(uri) {
  try {
    const u = new URL(uri);
    if (u.protocol !== 'otpauth:') return null;
    const label = decodeURIComponent(u.pathname.replace(/^\/+/, ''));
    const [maybeIssuer, account] = label.includes(':') ? label.split(':') : [null, label];
    return {
      name: account?.trim() || label,
      issuer: u.searchParams.get('issuer') || maybeIssuer || '',
      secret: u.searchParams.get('secret') || '',
      digits: parseInt(u.searchParams.get('digits') || '6', 10),
      period: parseInt(u.searchParams.get('period') || '30', 10),
      algorithm: (u.searchParams.get('algorithm') || 'SHA1').toUpperCase()
    };
  } catch { return null; }
}

export function buildOtpauth({ name, issuer, secret, digits = 6, period = 30, algorithm = 'SHA1' }) {
  const label = issuer ? `${issuer}:${name}` : name;
  const p = new URLSearchParams({ secret, digits, period, algorithm });
  if (issuer) p.set('issuer', issuer);
  return `otpauth://totp/${encodeURIComponent(label)}?${p}`;
}
