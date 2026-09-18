/**
 * import.js — Passwörter und 2FA-Codes aus anderen Programmen übernehmen.
 *
 * Gelesen wird nur, was die Programme **unverschlüsselt** exportieren; ein
 * verschlüsselter Export wird erkannt und mit einem Hinweis abgelehnt.
 *
 *   CSV   Bitwarden, 1Password, LastPass, KeePassXC, Proton Pass, Dashlane,
 *         NordPass, Chrome/Edge/Brave, Firefox, Safari/Apple — über die
 *         Spaltennamen, nicht über eine feste Reihenfolge.
 *   JSON  Bitwarden, Proton Pass, Proton Authenticator, Aegis, 2FAS, andOTP.
 *   ZIP   der Export von Proton Pass (darin data.json).
 *   XML   KeePass 2 / KeePassXC („KeePass XML“).
 *   Text  eine otpauth://-Adresse je Zeile (auch otpauth-migration:// aus
 *         Google Authenticator).
 *
 * KeePass-Dateien (.kdbx) brauchen keinen Import — die öffnet WKeePass
 * direkt.
 *
 * Ergebnis ist immer dieselbe Form:
 *   { source, items: [{ name, username, password, url, notes, folder, tags,
 *                       totp: { secret, digits, period, algorithm } | null }] }
 */

import { parseOtpauth } from './totp.js';
import { parseMigration } from './qr.js';

/* =========================================================
   Einstieg
   ========================================================= */

/** @param {File} file */
export async function parseImport(file) {
  const bytes = new Uint8Array(await file.arrayBuffer());
  const text = bytes[0] === 0x50 && bytes[1] === 0x4b
    ? await textFromZip(bytes)
    : new TextDecoder().decode(bytes);
  return parseText(file.name, text);
}

function parseText(fileName, text) {
  const raw = String(text ?? '').replace(/^\uFEFF/, '');
  const trimmed = raw.trim();
  if (!trimmed) throw new Error('Die Datei ist leer.');

  if (trimmed.startsWith('<')) return fromKeePassXml(trimmed);

  if (/^[[{]/.test(trimmed)) {
    let data;
    try { data = JSON.parse(trimmed); }
    catch { throw new Error('Die JSON-Datei ist nicht lesbar.'); }
    return fromJson(data);
  }

  if (/^otpauth(-migration)?:\/\//im.test(trimmed) && !/[,;\t].*[,;\t]/.test(trimmed.split('\n')[0])) {
    return fromOtpList(trimmed);
  }

  return fromCsv(raw, fileName);
}

/* =========================================================
   2FA-Einträge
   ========================================================= */

function totpFrom(value, extra = {}) {
  const v = String(value ?? '').trim();
  if (!v) return null;
  if (/^otpauth:\/\//i.test(v)) {
    const p = parseOtpauth(v);
    return p?.secret ? { secret: p.secret, digits: p.digits, period: p.period, algorithm: p.algorithm, issuer: p.issuer, account: p.name } : null;
  }
  // Nackter Schlüssel (Base32), wie ihn die meisten CSV-Exporte enthalten
  const secret = v.replace(/[\s-]/g, '').toUpperCase();
  if (!/^[A-Z2-7]+=*$/.test(secret) || secret.length < 8) return null;
  return {
    secret: secret.replace(/=+$/, ''),
    digits: Number(extra.digits) || 6,
    period: Number(extra.period) || 30,
    algorithm: String(extra.algorithm || 'SHA1').toUpperCase().replace('-', '')
  };
}

function item(fields) {
  return {
    name: fields.name?.trim() || hostOf(fields.url) || fields.username || 'Ohne Namen',
    username: fields.username ?? '',
    password: fields.password ?? '',
    url: fields.url ?? '',
    notes: fields.notes ?? '',
    folder: fields.folder ?? '',
    tags: fields.tags ?? [],
    totp: fields.totp ?? null
  };
}

function hostOf(url) {
  try { return new URL(/^[a-z]+:\/\//i.test(url) ? url : `https://${url}`).hostname.replace(/^www\./, ''); }
  catch { return ''; }
}

function fromOtpList(text) {
  const items = [];
  for (const line of text.split(/\r?\n/).map(l => l.trim()).filter(Boolean)) {
    if (/^otpauth-migration:\/\//i.test(line)) {
      for (const a of parseMigration(line)) {
        if (a.type !== 'totp') continue;
        items.push(item({ name: a.issuer || a.name, username: a.name, totp: a }));
      }
      continue;
    }
    const p = parseOtpauth(line);
    if (p?.secret) items.push(item({ name: p.issuer || p.name, username: p.name, totp: totpFrom(line) }));
  }
  if (!items.length) throw new Error('In der Datei steht keine otpauth-Adresse.');
  return { source: '2FA-Liste', items };
}

/* =========================================================
   JSON
   ========================================================= */

function fromJson(data) {
  // Proton Pass: Tresore mit Einträgen
  if (data?.vaults && typeof data.vaults === 'object') {
    if (data.encrypted) throw new Error('Der Proton-Pass-Export ist verschlüsselt. Bitte ohne PGP exportieren.');
    return fromProtonPass(data);
  }

  // Proton Authenticator
  if (Array.isArray(data?.entries) && data.entries.some(e => e?.content?.uri)) {
    return fromProtonAuthenticator(data);
  }

  // Bitwarden
  if (data?.encrypted === true) throw new Error('Der Bitwarden-Export ist verschlüsselt. Bitte als „.json“ ohne Passwortschutz exportieren.');
  if (Array.isArray(data?.items) && ('folders' in data || data.items.some(i => 'login' in i))) {
    return fromBitwarden(data);
  }

  // Aegis
  if (data?.db !== undefined && data?.header) {
    if (typeof data.db === 'string') throw new Error('Der Aegis-Export ist verschlüsselt. Bitte unverschlüsselt exportieren.');
    return fromAegis(data.db);
  }

  // 2FAS
  if (Array.isArray(data?.services) || data?.servicesEncrypted) {
    if (data.servicesEncrypted && !data.services?.length) throw new Error('Der 2FAS-Export ist verschlüsselt. Bitte ohne Passwort exportieren.');
    return from2fas(data);
  }

  // andOTP: eine Liste von Konten
  if (Array.isArray(data) && data.some(e => e?.secret)) {
    return fromAndOtp(data);
  }

  throw new Error('Dieses JSON-Format ist unbekannt. Unterstützt: Bitwarden, Proton, Aegis, 2FAS, andOTP.');
}

function fromProtonPass(data) {
  const items = [];
  for (const vault of Object.values(data.vaults)) {
    for (const it of vault.items ?? []) {
      if (it.state === 2) continue;   // im Papierkorb
      const d = it.data ?? {};
      const c = d.content ?? {};
      const meta = d.metadata ?? {};
      if (d.type !== 'login' && d.type !== 'note') continue;
      const extra = (d.extraFields ?? [])
        .map(f => `${f.fieldName}: ${f.data?.content ?? f.data?.totpUri ?? ''}`);
      items.push(item({
        name: meta.name,
        username: c.itemUsername || c.itemEmail || c.username || '',
        password: c.password ?? '',
        url: c.urls?.[0] ?? '',
        notes: [meta.note, ...extra].filter(Boolean).join('\n'),
        folder: vault.name ?? '',
        totp: totpFrom(c.totpUri)
      }));
    }
  }
  return { source: 'Proton Pass', items };
}

function fromProtonAuthenticator(data) {
  const items = [];
  for (const e of data.entries) {
    const t = totpFrom(e.content?.uri);
    if (!t) continue;
    items.push(item({ name: t.issuer || e.content?.name, username: t.account ?? e.content?.name ?? '', notes: e.note ?? '', totp: t }));
  }
  return { source: 'Proton Authenticator', items };
}

/* =========================================================
   KeePass-XML
   ========================================================= */

function fromKeePassXml(text) {
  const doc = new DOMParser().parseFromString(text, 'application/xml');
  if (doc.querySelector('parsererror')) throw new Error('Die XML-Datei ist nicht lesbar.');
  const root = doc.querySelector('KeePassFile > Root > Group');
  if (!root) throw new Error('Das ist keine KeePass-XML-Datei.');

  // Der Papierkorb kommt nicht mit.
  const recycleBin = doc.querySelector('Meta > RecycleBinUUID')?.textContent;
  const items = [];

  const walk = (group, path) => {
    if (recycleBin && group.querySelector(':scope > UUID')?.textContent === recycleBin) return;

    for (const entry of group.querySelectorAll(':scope > Entry')) {
      const f = {};
      for (const str of entry.querySelectorAll(':scope > String')) {
        f[str.querySelector('Key')?.textContent ?? ''] = str.querySelector('Value')?.textContent ?? '';
      }
      // KeePass 2 speichert TOTP als „TOTP Seed“ + „TOTP Settings“ (Periode;Stellen),
      // KeePassXC als otpauth-Adresse unter „otp“.
      const settings = (f['TOTP Settings'] ?? '').split(';');
      items.push(item({
        name: f.Title, username: f.UserName, password: f.Password, url: f.URL, notes: f.Notes,
        folder: path,
        tags: (entry.querySelector(':scope > Tags')?.textContent ?? '').split(/[,;]/).map(t => t.trim()).filter(Boolean),
        totp: totpFrom(f.otp || f['TOTP Seed'] || f['TimeOtp-Secret-Base32'], { period: settings[0], digits: settings[1] })
      }));
    }
    for (const sub of group.querySelectorAll(':scope > Group')) {
      const name = sub.querySelector(':scope > Name')?.textContent ?? '';
      walk(sub, path ? `${path}/${name}` : name);
    }
  };
  walk(root, '');
  return { source: 'KeePass', items };
}

/* =========================================================
   ZIP — nur so viel, wie der Export von Proton Pass braucht
   ========================================================= */

async function textFromZip(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  // Das Inhaltsverzeichnis steht am Ende
  let eocd = -1;
  for (let i = bytes.length - 22; i >= Math.max(0, bytes.length - 65557); i--) {
    if (view.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('Die ZIP-Datei ist beschädigt.');

  let pos = view.getUint32(eocd + 16, true);
  const count = view.getUint16(eocd + 10, true);
  const found = [];
  for (let n = 0; n < count; n++) {
    if (view.getUint32(pos, true) !== 0x02014b50) break;
    const nameLen = view.getUint16(pos + 28, true);
    found.push({
      method: view.getUint16(pos + 10, true),
      size: view.getUint32(pos + 20, true),
      local: view.getUint32(pos + 42, true),
      name: new TextDecoder().decode(bytes.subarray(pos + 46, pos + 46 + nameLen))
    });
    pos += 46 + nameLen + view.getUint16(pos + 30, true) + view.getUint16(pos + 32, true);
  }

  const want = found.find(f => /(^|\/)data\.json$/i.test(f.name))
    ?? found.find(f => /\.(json|csv|xml|txt)$/i.test(f.name));
  if (!want) throw new Error('In der ZIP-Datei steckt kein bekannter Export.');
  if (/\.pgp$/i.test(want.name)) throw new Error('Der Export ist verschlüsselt. Bitte ohne PGP exportieren.');

  const start = want.local + 30 + view.getUint16(want.local + 26, true) + view.getUint16(want.local + 28, true);
  const data = bytes.subarray(start, start + want.size);
  if (want.method === 0) return new TextDecoder().decode(data);
  if (want.method !== 8) throw new Error('Diese ZIP-Kompression wird nicht unterstützt — bitte entpacken.');
  if (typeof DecompressionStream === 'undefined') throw new Error('ZIP wird hier nicht unterstützt — bitte die Datei vorher entpacken.');

  const stream = new Blob([data]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
  return new Response(stream).text();
}

function fromBitwarden(data) {
  const folders = new Map((data.folders ?? []).map(f => [f.id, f.name]));
  const items = [];
  for (const it of data.items ?? []) {
    // 1 Zugang, 2 Notiz; Karten und Identitäten als Notiz mit den Feldern
    const login = it.login ?? {};
    const extra = (it.fields ?? []).filter(f => f.name).map(f => `${f.name}: ${f.value ?? ''}`);
    items.push(item({
      name: it.name,
      username: login.username ?? '',
      password: login.password ?? '',
      url: login.uris?.[0]?.uri ?? '',
      notes: [it.notes, ...extra, ...details(it.card), ...details(it.identity)].filter(Boolean).join('\n'),
      folder: folders.get(it.folderId) ?? '',
      totp: totpFrom(login.totp)
    }));
  }
  return { source: 'Bitwarden', items };
}

function details(obj) {
  if (!obj) return [];
  return Object.entries(obj).filter(([, v]) => v).map(([k, v]) => `${k}: ${v}`);
}

function fromAegis(db) {
  const groups = new Map((db.groups ?? []).map(g => [g.uuid, g.name]));
  const items = [];
  for (const e of db.entries ?? []) {
    if (e.type !== 'totp' && e.type !== 'steam') continue;
    const info = e.info ?? {};
    items.push(item({
      name: e.issuer || e.name,
      username: e.name ?? '',
      notes: e.note ?? '',
      folder: groups.get(e.groups?.[0]) ?? '',
      totp: totpFrom(info.secret, { digits: info.digits, period: info.period, algorithm: info.algo })
    }));
  }
  return { source: 'Aegis', items };
}

function from2fas(data) {
  const groups = new Map((data.groups ?? []).map(g => [g.id, g.name]));
  const items = [];
  for (const s of data.services ?? []) {
    const otp = s.otp ?? {};
    if (otp.tokenType && otp.tokenType !== 'TOTP' && otp.tokenType !== 'STEAM') continue;
    items.push(item({
      name: otp.issuer || s.name,
      username: otp.account ?? otp.label ?? '',
      folder: groups.get(s.groupId) ?? '',
      totp: totpFrom(s.secret, { digits: otp.digits, period: otp.period, algorithm: otp.algorithm })
    }));
  }
  return { source: '2FAS', items };
}

function fromAndOtp(list) {
  const items = [];
  for (const e of list) {
    if (e.type && e.type !== 'TOTP' && e.type !== 'STEAM') continue;
    const label = e.label ?? '';
    items.push(item({
      name: e.issuer || label,
      username: label.includes(':') ? label.split(':').slice(1).join(':') : label,
      tags: e.tags ?? [],
      totp: totpFrom(e.secret, { digits: e.digits, period: e.period, algorithm: e.algorithm })
    }));
  }
  return { source: 'andOTP', items };
}

/* =========================================================
   CSV
   ========================================================= */

/** RFC 4180: Anführungszeichen, verdoppelte "" und Zeilenumbrüche im Feld. */
function parseCsv(text) {
  const first = text.split(/\r?\n/, 1)[0];
  const sep = [',', ';', '\t'].map(c => [c, first.split(c).length]).sort((a, b) => b[1] - a[1])[0][0];

  const rows = [];
  let row = [], field = '', quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') { field += '"'; i++; }
      else if (c === '"') quoted = false;
      else field += c;
    } else if (c === '"') quoted = true;
    else if (c === sep) { row.push(field); field = ''; }
    else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++;
      row.push(field); field = '';
      if (row.some(f => f !== '')) rows.push(row);
      row = [];
    } else field += c;
  }
  row.push(field);
  if (row.some(f => f !== '')) rows.push(row);
  return rows;
}

/** Spaltennamen der bekannten Programme → unser Feld. Klein geschrieben. */
const COLUMNS = {
  name: ['name', 'title', 'titel', 'account', 'item name'],
  url: ['url', 'login_uri', 'website', 'uri', 'urls', 'web site', 'login url'],
  username: ['username', 'login_username', 'login', 'user', 'user name', 'benutzername', 'username1'],
  email: ['email', 'e-mail', 'mail'],
  password: ['password', 'login_password', 'passwort', 'kennwort'],
  totp: ['totp', 'login_totp', 'otpauth', 'otp', 'otpsecret', 'otp secret', 'one-time password', '2fa', 'otp auth'],
  notes: ['notes', 'note', 'extra', 'comments', 'notizen', 'notiz'],
  folder: ['folder', 'group', 'grouping', 'vault', 'category', 'ordner', 'gruppe'],
  tags: ['tags', 'labels']
};

function sourceOf(header, fileName) {
  const h = header.join(',');
  if (h.includes('login_uri')) return 'Bitwarden';
  if (h.includes('grouping') && h.includes('extra')) return 'LastPass';
  if (h.includes('httprealm')) return 'Firefox';
  if (h.includes('otpauth') && h.includes('archived')) return '1Password';
  if (h.includes('last modified') && h.includes('group')) return 'KeePassXC';
  if (h.includes('vault') && h.includes('createtime')) return 'Proton Pass';
  if (h.includes('username2')) return 'Dashlane';
  if (h.includes('cardholdername')) return 'NordPass';
  if (/^name,url,username,password/.test(h)) return 'Chrome';
  if (h.includes('otpauth')) return 'Apple';
  return fileName?.replace(/\.[^.]+$/, '') || 'CSV';
}

function fromCsv(text, fileName) {
  const rows = parseCsv(text);
  if (rows.length < 2) throw new Error('In der CSV-Datei stehen keine Einträge.');

  const header = rows[0].map(h => h.trim().toLowerCase());
  const col = {};
  for (const [key, names] of Object.entries(COLUMNS)) {
    const i = header.findIndex(h => names.includes(h));
    if (i >= 0) col[key] = i;
  }
  if (col.password === undefined && col.totp === undefined) {
    throw new Error('Keine Spalte „password“ oder „totp“ gefunden — ist das ein Export aus einem Passwortmanager?');
  }

  const items = [];
  for (const r of rows.slice(1)) {
    const get = k => (col[k] !== undefined ? (r[col[k]] ?? '').trim() : '');
    // KeePassXC: Gruppe beginnt mit dem Namen der Wurzel — die fällt weg
    const folder = get('folder').replace(/^Root\/?/i, '');
    const it = item({
      name: get('name'),
      username: get('username') || get('email'),
      password: r[col.password] ?? '',
      url: get('url'),
      notes: get('notes'),
      folder,
      tags: get('tags').split(/[,;]/).map(t => t.trim()).filter(Boolean),
      totp: totpFrom(get('totp'))
    });
    if (it.password || it.totp || it.username || it.url) items.push(it);
  }
  return { source: sourceOf(header, fileName), items };
}
