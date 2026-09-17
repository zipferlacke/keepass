//! Die App-PIN und die damit freigeschalteten Datenbanken.
//!
//! # Das Modell
//!
//! Es gibt **eine** PIN für das ganze Programm. Sie wird einmal am Anfang
//! festgelegt und ergibt zusammen mit dem Zufallsschlüssel `K` aus dem
//! Schlüsselbund den *App-Schlüssel*:
//!
//! ```text
//! PIN  --Argon2id(Salz)-->  ⊕ K  -->  App-Schlüssel
//! ```
//!
//! Für **jede Datenbank einzeln** entscheidest du dann, ob sie damit
//! geöffnet werden darf. Ist sie freigeschaltet, liegt ihr Master-Passwort
//! hier verschlüsselt:
//!
//! ```text
//! pin:  mit dem App-Schlüssel   (PIN nötig)
//! bio:  nur mit K               (Fingerabdruck als Nachweis davor)
//! ```
//!
//! Der Unterschied ist wesentlich: Beim PIN-Weg braucht ein Angreifer zwei
//! Geheimnisse, `K` und die PIN. Beim Finger-Weg nur `K` — der Fingerabdruck
//! belegt, dass du es bist, er ist kein zweites Geheimnis. Die Prüfung
//! fällt unter Linux und macOS in diesem Programm.
//!
//! Windows Hello geht einen dritten, stärkeren Weg ohne PIN: Dort ist die
//! Biometrie selbst der Schlüssel. Siehe den Abschnitt „Gerätegebunden".
//!
//! # Der Prüfblock
//!
//! Damit sich eine falsche PIN erkennen lässt, ohne dass eine Datenbank
//! freigeschaltet sein muss, liegt ein fester Text mit dem App-Schlüssel
//! verschlüsselt daneben. Geht der auf, war die PIN richtig.
//!
//! # Was das kostet
//!
//! Ohne Schlüsselbund hängt alles allein an der PIN — rund zwanzig Bit, die
//! Argon2id teuer macht, aber nicht unmöglich. Das Master-Passwort bleibt
//! deshalb immer der Hauptschlüssel, und eine Wiederherstellung der PIN gibt
//! es bewusst nicht: Sie wäre eine Hintertür.

use std::collections::BTreeMap;
use std::path::PathBuf;

use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::Manager;
use zeroize::Zeroizing;

use crate::keystore;
use crate::util::write_atomic;

/// Nach so vielen Fehlversuchen wird alles verworfen.
///
/// Das hält Gelegenheitsversuche am offenen Gerät auf. Gegen jemanden, der
/// die Datei kopiert hat, hilft es nicht — der zählt nicht mit.
const MAX_FAILURES: u32 = 5;

const M_COST: u32 = 65_536;
const T_COST: u32 = 3;
const P_COST: u32 = 1;

const PIN_INFO: &[u8] = b"wkeepass-app-pin-v3";
const BIO_INFO: &[u8] = b"wkeepass-app-bio-v3";
const CHECK_TEXT: &str = "wkeepass-pin-ok";

#[derive(Serialize, Deserialize, Clone)]
struct Wrapped {
    nonce: String,
    ciphertext: String,
}

/// Was für eine einzelne Datenbank freigeschaltet ist.
#[derive(Serialize, Deserialize, Clone, Default)]
struct DbSeal {
    #[serde(default)]
    pin: Option<Wrapped>,
    #[serde(default)]
    bio: Option<Wrapped>,
}

#[derive(Serialize, Deserialize)]
struct AppSeal {
    version: u8,
    salt: String,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    /// Fester Text, mit dem App-Schlüssel verschlüsselt.
    check: Wrapped,
    uses_keyring: bool,
    #[serde(default)]
    failures: u32,
    /// Datenbankpfad → was dafür hinterlegt ist.
    #[serde(default)]
    databases: BTreeMap<String, DbSeal>,
}

/* =========================================================
   Auskunft
   ========================================================= */

/// Zustand der App-PIN, unabhängig von einer Datenbank.
pub struct Status {
    pub pin_set: bool,
}

pub fn status(app: &tauri::AppHandle) -> Status {
    Status { pin_set: read(app).is_some() }
}

/// Was für **diese** Datenbank bereitsteht.
pub struct Offer {
    pub pin: bool,
    pub biometric: bool,
    pub keyring: bool,
}

pub fn offer(app: &tauri::AppHandle, path: Option<&str>) -> Offer {
    let sealed = read(app);
    let entry = path
        .and_then(|p| sealed.as_ref().and_then(|s| s.databases.get(p)))
        .cloned()
        .unwrap_or_default();

    Offer {
        pin: entry.pin.is_some(),
        biometric: entry.bio.is_some() && crate::biometric::available(),
        keyring: keystore::available(),
    }
}

/* =========================================================
   Die App-PIN
   ========================================================= */

/// Legt die PIN des Programms an. Eine vorhandene wird dabei ersetzt —
/// samt aller Freigaben, denn die hängen am alten Schlüssel.
pub fn create_pin(app: &tauri::AppHandle, pin: &str) -> Result<(), String> {
    check_pin(pin)?;

    let k = fresh_keyring_key()?;

    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let key = derive(pin, &salt, M_COST, T_COST, P_COST, k.as_deref())?;

    write(app, &AppSeal {
        version: 3,
        salt: B64.encode(salt),
        m_cost: M_COST,
        t_cost: T_COST,
        p_cost: P_COST,
        check: wrap(&key, CHECK_TEXT)?,
        uses_keyring: k.is_some(),
        failures: 0,
        databases: BTreeMap::new(),
    })
}

/// Ändert die PIN und wickelt alle Freigaben auf den neuen Schlüssel um.
pub fn change_pin(app: &tauri::AppHandle, old: &str, new: &str) -> Result<(), String> {
    check_pin(new)?;

    let mut sealed = read(app).ok_or("Es ist keine PIN festgelegt.")?;
    let old_key = verify(app, &mut sealed, old)?;
    let k = load_keyring_key(&sealed)?;

    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let new_key = derive(new, &salt, M_COST, T_COST, P_COST, k.as_deref())?;

    // Jede freigeschaltete Datenbank einmal umwickeln.
    let mut databases = BTreeMap::new();
    for (path, entry) in &sealed.databases {
        let pin = match &entry.pin {
            Some(w) => Some(wrap(&new_key, &unwrap(&old_key, w)?)?),
            None => None,
        };
        // Der Finger-Weg hängt nur an K und bleibt unberührt.
        databases.insert(path.clone(), DbSeal { pin, bio: entry.bio.clone() });
    }

    sealed.salt = B64.encode(salt);
    sealed.m_cost = M_COST;
    sealed.t_cost = T_COST;
    sealed.p_cost = P_COST;
    sealed.check = wrap(&new_key, CHECK_TEXT)?;
    sealed.failures = 0;
    sealed.databases = databases;

    write(app, &sealed)
}

/// Verwirft PIN, Schlüssel und sämtliche Freigaben.
pub fn clear(app: &tauri::AppHandle) -> Result<(), String> {
    let _ = keystore::clear();

    match std::fs::remove_file(seal_path(app)?) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("Siegel konnte nicht entfernt werden: {e}")),
    }
}

/// Prüft die PIN, ohne etwas zu öffnen — für „ich bin es".
pub fn confirm_pin(app: &tauri::AppHandle, pin: &str) -> Result<(), String> {
    let mut sealed = read(app).ok_or("Es ist keine PIN festgelegt.")?;
    verify(app, &mut sealed, pin).map(|_| ())
}

/* =========================================================
   Datenbanken freischalten
   ========================================================= */

/// Schaltet eine Datenbank für PIN und/oder Fingerabdruck frei.
///
/// `master` kommt aus dem Kern, nicht aus der Oberfläche. Die PIN wird
/// gebraucht, weil ohne sie kein App-Schlüssel entsteht.
pub fn remember(
    app: &tauri::AppHandle,
    path: &str,
    master: &str,
    pin: &str,
    allow_pin: bool,
    allow_biometric: bool,
) -> Result<(), String> {
    let mut sealed = read(app).ok_or("Es ist noch keine PIN festgelegt.")?;
    let key = verify(app, &mut sealed, pin)?;
    let k = load_keyring_key(&sealed)?;

    if allow_biometric && k.is_none() {
        return Err("Ohne Schlüsselbund lässt sich der Fingerabdruck nicht absichern.".into());
    }

    let entry = DbSeal {
        pin: if allow_pin { Some(wrap(&key, master)?) } else { None },
        bio: match (allow_biometric, k.as_deref()) {
            (true, Some(k)) => Some(wrap(&mix(&[], k, BIO_INFO), master)?),
            _ => None,
        },
    };

    if entry.pin.is_none() && entry.bio.is_none() {
        sealed.databases.remove(path);
    } else {
        sealed.databases.insert(path.to_string(), entry);
    }

    write(app, &sealed)
}

/// Nimmt die Freigabe einer Datenbank zurück.
pub fn forget(app: &tauri::AppHandle, path: &str) -> Result<(), String> {
    forget_device(app, path)?;
    let Some(mut sealed) = read(app) else { return Ok(()) };
    sealed.databases.remove(path);
    write(app, &sealed)
}

/* =========================================================
   Öffnen
   ========================================================= */

pub fn unseal_with_pin(
    app: &tauri::AppHandle,
    path: &str,
    pin: &str,
) -> Result<Zeroizing<String>, String> {
    let mut sealed = read(app).ok_or("Es ist keine PIN festgelegt.")?;
    let key = verify(app, &mut sealed, pin)?;

    let wrapped = sealed
        .databases
        .get(path)
        .and_then(|e| e.pin.clone())
        .ok_or("Diese Datenbank ist nicht für die PIN freigeschaltet.")?;

    unwrap(&key, &wrapped).map_err(|_| "Das Siegel passt nicht mehr.".to_string())
}

/// Öffnet über den Fingerabdruck. Die Prüfung selbst macht `system.rs`.
pub fn unseal_with_biometric(
    app: &tauri::AppHandle,
    path: &str,
) -> Result<Zeroizing<String>, String> {
    let sealed = read(app).ok_or("Es ist keine PIN festgelegt.")?;

    let wrapped = sealed
        .databases
        .get(path)
        .and_then(|e| e.bio.clone())
        .ok_or("Diese Datenbank ist nicht für den Fingerabdruck freigeschaltet.")?;

    let k = load_keyring_key(&sealed)?
        .ok_or("Der Schlüsselbund ist nicht erreichbar — bitte PIN oder Master-Passwort.")?;

    unwrap(&mix(&[], k.as_ref(), BIO_INFO), &wrapped)
        .map_err(|_| "Das Siegel passt nicht mehr zum Schlüsselbund.".to_string())
}

/* =========================================================
   Gerätegebunden: Windows Hello
   ---------------------------------------------------------
   Ein eigenes Siegel neben dem der PIN, in `device.json`.

   Hier ist die Biometrie kein Nachweis vor dem Schlüsselbund, sondern
   selbst der Schlüssel: Das TPM signiert einen Zufallswert erst nach der
   Prüfung, und aus der Signatur entsteht der Schlüssel (biometric.rs).
   Wer die Datei kopiert, kann damit nichts anfangen — ohne dieses Gerät
   und ohne Finger bzw. Gesicht gibt es keine Signatur.

   Deshalb braucht dieser Weg **keine PIN**. Er ersetzt beim Öffnen PIN
   und Master-Passwort, und er bleibt bestehen, wenn die PIN entfernt wird.
   ========================================================= */

#[derive(Serialize, Deserialize)]
struct DeviceSeal {
    version: u8,
    /// Der Zufallswert, den das Gerät signiert. Nicht geheim.
    challenge: String,
    /// Datenbankpfad → Master-Passwort, verschlüsselt.
    #[serde(default)]
    databases: BTreeMap<String, Wrapped>,
}

/// Ist diese Datenbank gerätegebunden freigeschaltet — und kann das Gerät
/// das gerade auch einlösen?
pub fn device_offer(app: &tauri::AppHandle, path: Option<&str>) -> bool {
    let Some(path) = path else { return false };
    read_device(app).is_some_and(|s| s.databases.contains_key(path))
        && crate::biometric::device_key_available()
}

/// Versiegelt das Master-Passwort mit dem Geräteschlüssel.
///
/// Fragt dabei Windows Hello ab — beim allerersten Mal zweimal, weil das
/// Anlegen des Schlüssels im TPM selbst eine Prüfung verlangt.
pub fn remember_device(app: &tauri::AppHandle, path: &str, master: &str) -> Result<(), String> {
    let mut sealed = match read_device(app) {
        Some(sealed) => sealed,
        None => {
            let mut challenge = [0u8; 32];
            OsRng.fill_bytes(&mut challenge);
            DeviceSeal { version: 1, challenge: B64.encode(challenge), databases: BTreeMap::new() }
        }
    };

    let key = crate::biometric::device_key(&decode(&sealed.challenge)?)?;
    sealed.databases.insert(path.to_string(), wrap(&key, master)?);
    write_device(app, &sealed)
}

/// Nimmt die gerätegebundene Freigabe einer Datenbank zurück.
pub fn forget_device(app: &tauri::AppHandle, path: &str) -> Result<(), String> {
    let Some(mut sealed) = read_device(app) else { return Ok(()) };
    if sealed.databases.remove(path).is_none() {
        return Ok(());
    }
    write_device(app, &sealed)
}

/// Öffnet über den Geräteschlüssel. Die Prüfung passiert dabei — ein
/// vorgeschaltetes `biometric::verify` braucht es nicht.
pub fn unseal_with_device(app: &tauri::AppHandle, path: &str) -> Result<Zeroizing<String>, String> {
    let sealed = read_device(app).ok_or("Auf diesem Gerät ist nichts freigeschaltet.")?;

    let wrapped = sealed
        .databases
        .get(path)
        .ok_or("Diese Datenbank ist hier nicht freigeschaltet.")?;

    let key = crate::biometric::device_key(&decode(&sealed.challenge)?)?;

    unwrap(&key, wrapped).map_err(|_| {
        "Das Siegel passt nicht mehr zum Gerät — bitte mit dem Master-Passwort öffnen \
         und die Freigabe neu einrichten."
            .to_string()
    })
}

fn device_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    Ok(seal_path(app)?.with_file_name("device.json"))
}

fn read_device(app: &tauri::AppHandle) -> Option<DeviceSeal> {
    let raw = std::fs::read_to_string(device_path(app).ok()?).ok()?;
    serde_json::from_str(&raw).ok()
}

fn write_device(app: &tauri::AppHandle, sealed: &DeviceSeal) -> Result<(), String> {
    let json = serde_json::to_vec_pretty(sealed).map_err(|e| e.to_string())?;
    write_atomic(&device_path(app)?, &json)
}

/* =========================================================
   Schlüssel
   ========================================================= */

/// Prüft die PIN am Prüfblock und zählt Fehlversuche mit.
fn verify(
    app: &tauri::AppHandle,
    sealed: &mut AppSeal,
    pin: &str,
) -> Result<Zeroizing<[u8; 32]>, String> {
    if sealed.failures >= MAX_FAILURES {
        clear(app)?;
        return Err("Zu viele Fehlversuche. Die PIN wurde verworfen.".into());
    }

    let salt = decode(&sealed.salt)?;
    let k = load_keyring_key(sealed)?;
    let key = derive(pin, &salt, sealed.m_cost, sealed.t_cost, sealed.p_cost, k.as_deref())?;

    // Poly1305 schlägt fehl, wenn die PIN falsch war — oder wenn jemand an
    // der Datei war. Beides führt hierher.
    if unwrap(&key, &sealed.check).is_err() {
        sealed.failures += 1;
        let left = MAX_FAILURES.saturating_sub(sealed.failures);
        write(app, sealed)?;

        return Err(if left == 0 {
            "PIN falsch. Die PIN wurde verworfen.".into()
        } else {
            format!("PIN falsch. Noch {left} Versuche.")
        });
    }

    if sealed.failures != 0 {
        sealed.failures = 0;
        write(app, sealed)?;
    }
    Ok(key)
}

/// Mischt zwei Geheimnisse zu einem Schlüssel.
///
/// SHA-256 genügt: Beide Eingaben sind bereits gleichverteilt — die eine
/// kommt aus Argon2, die andere aus dem Zufallsgenerator. Eine
/// Extraktionsstufe wie bei HKDF brächte hier nichts dazu.
fn mix(a: &[u8], b: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(info);
    hasher.update((a.len() as u32).to_le_bytes());
    hasher.update(a);
    hasher.update(b);
    Zeroizing::new(hasher.finalize().into())
}

fn derive(
    pin: &str,
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    k: Option<&[u8; 32]>,
) -> Result<Zeroizing<[u8; 32]>, String> {
    let params = Params::new(m_cost, t_cost, p_cost, Some(32))
        .map_err(|e| format!("Argon2-Parameter ungültig: {e}"))?;

    let mut from_pin = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(pin.as_bytes(), salt, from_pin.as_mut())
        .map_err(|e| format!("Schlüsselableitung fehlgeschlagen: {e}"))?;

    Ok(mix(from_pin.as_ref(), k.map(|k| &k[..]).unwrap_or(&[]), PIN_INFO))
}

fn wrap(key: &[u8; 32], plain: &str) -> Result<Wrapped, String> {
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);

    let ciphertext = XChaCha20Poly1305::new(Key::from_slice(key))
        .encrypt(XNonce::from_slice(&nonce), plain.as_bytes())
        .map_err(|_| "Verschlüsseln fehlgeschlagen.".to_string())?;

    Ok(Wrapped { nonce: B64.encode(nonce), ciphertext: B64.encode(ciphertext) })
}

fn unwrap(key: &[u8; 32], wrapped: &Wrapped) -> Result<Zeroizing<String>, String> {
    let nonce = decode(&wrapped.nonce)?;
    let ciphertext = decode(&wrapped.ciphertext)?;

    let plain = XChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(XNonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| "Entschlüsseln fehlgeschlagen.".to_string())?;

    String::from_utf8(plain)
        .map(Zeroizing::new)
        .map_err(|_| "Siegel beschädigt.".to_string())
}

fn fresh_keyring_key() -> Result<Option<Zeroizing<[u8; 32]>>, String> {
    if !keystore::available() {
        return Ok(None);
    }

    let mut k = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(k.as_mut());
    keystore::store(&k)?;
    Ok(Some(k))
}

fn load_keyring_key(sealed: &AppSeal) -> Result<Option<Zeroizing<[u8; 32]>>, String> {
    if !sealed.uses_keyring {
        return Ok(None);
    }

    keystore::load()?.map(Some).ok_or_else(|| {
        "Der Schlüssel im Schlüsselbund fehlt — bitte die PIN neu festlegen.".to_string()
    })
}

/* =========================================================
   Datei
   ========================================================= */

fn seal_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_config_dir()
        .map_err(|e| format!("Kein Konfigurationsverzeichnis: {e}"))?;
    Ok(dir.join("sealed.json"))
}

fn read(app: &tauri::AppHandle) -> Option<AppSeal> {
    let raw = std::fs::read_to_string(seal_path(app).ok()?).ok()?;
    serde_json::from_str(&raw).ok()
}

fn write(app: &tauri::AppHandle, sealed: &AppSeal) -> Result<(), String> {
    let json = serde_json::to_vec_pretty(sealed).map_err(|e| e.to_string())?;
    write_atomic(&seal_path(app)?, &json)
}

fn decode(value: &str) -> Result<Vec<u8>, String> {
    B64.decode(value).map_err(|_| "Siegel beschädigt.".to_string())
}

fn check_pin(pin: &str) -> Result<(), String> {
    if pin.chars().count() < 4 {
        return Err("Die PIN muss mindestens vier Zeichen haben.".into());
    }
    Ok(())
}
