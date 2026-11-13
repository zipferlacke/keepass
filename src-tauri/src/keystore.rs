//! Der Zufallsschlüssel `K` im Schlüsselbund des Systems.
//!
//! `K` besteht aus 32 Byte Zufall und wird weder angezeigt noch exportiert
//! noch in eigenen Dateien gespeichert. Er ist die zweite Zutat neben der PIN
//! (siehe `seal.rs`) und beim Entsperren per Fingerabdruck die einzige.
//!
//! # Zweck
//!
//! Ohne `K` ließe sich die PIN anhand der Datei offline durchprobieren; eine
//! sechsstellige PIN wäre binnen Stunden gebrochen. Mit `K` braucht ein
//! Angreifer zusätzlich Zugriff auf die angemeldete Sitzung.
//!
//! # Schutzniveau je System
//!
//! ```text
//! macOS     Keychain, dahinter die Secure Enclave  — hardwaregebunden
//! Windows   Credential Manager, dahinter das TPM   — hardwaregebunden
//! Linux     Secret Service (gnome-keyring, ksecretd), an das
//!           Anmeldepasswort gebunden; die Datei ist offline angreifbar.
//! Android   kein Secret Service. `K` liegt in einer Datei im privaten
//!           Verzeichnis der App, für andere Anwendungen unlesbar (ohne
//!           Root), aber nicht an einen Chip gebunden.
//!
//!           Für den Fingerabdruck wird `K` dort nicht benötigt: Er nutzt den
//!           hardwaregebundenen Android-Keystore (`biometric::device_key`)
//!           ohne Datei und ohne PIN. `K` dient nur dem PIN-Weg.
//! ```
//!
//! Ein TPM unter x86-Linux würde Fehlversuche selbst zählen und die PIN
//! stärker absichern (`tss-esapi`); das ist nicht umgesetzt.

use zeroize::Zeroizing;

// Android hat einen eigenen Weg (unten) und keinen Schlüsselbund.
#[cfg(not(target_os = "android"))]
const SERVICE: &str = "de.wuefl.wkeepass";
#[cfg(not(target_os = "android"))]
const ACCOUNT: &str = "master-key";

/// Zustand des Schlüsselbunds.
///
/// Ein gesperrter Schlüsselbund ist von einem fehlenden zu unterscheiden.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum Availability {
    /// Ein Dienst antwortet und gibt Werte heraus.
    Ready,
    /// Ein Dienst existiert, ist aber gesperrt. Unter Linux tritt das bei
    /// Anmeldung per Fingerabdruck oder automatischer Anmeldung auf, da der
    /// Dienst dann kein Passwort zum Entsperren erhält. Auf Android gibt es
    /// diesen Fall nicht.
    #[cfg_attr(target_os = "android", allow(dead_code))]
    Locked,
    /// Kein Dienst vorhanden: minimale Installation, Android oder kein Dienst
    /// auf dem Bus.
    Missing,
}

#[cfg(target_os = "android")]
pub use android::{availability, clear, load, store};

#[cfg(not(target_os = "android"))]
pub fn availability() -> Availability {
    match keyring::Entry::store_status() {
        Err(_) => Availability::Missing,
        Ok(()) => match keyring::Entry::new(SERVICE, ACCOUNT) {
            Err(_) => Availability::Missing,
            // Kein Eintrag: Der Speicher ist verfügbar, enthält aber noch
            // keinen Wert.
            Ok(entry) => match entry.get_secret() {
                Ok(_) | Err(keyring::Error::NoEntry) => Availability::Ready,
                Err(keyring::Error::NoStorageAccess(_)) => Availability::Locked,
                Err(_) => Availability::Missing,
            },
        },
    }
}

pub fn available() -> bool {
    availability() == Availability::Ready
}

/// Legt `K` ab und überschreibt einen vorhandenen Wert.
#[cfg(not(target_os = "android"))]
pub fn store(key: &[u8; 32]) -> Result<(), String> {
    entry()?
        .set_secret(key)
        .map_err(|e| format!("Schlüsselbund nimmt den Wert nicht an: {e}"))
}

/// Holt `K` zurück. `None`: Es ist keiner hinterlegt.
#[cfg(not(target_os = "android"))]
pub fn load() -> Result<Option<Zeroizing<[u8; 32]>>, String> {
    match entry()?.get_secret() {
        Ok(bytes) => {
            let slice: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| "Der Wert im Schlüsselbund hat die falsche Länge.".to_string())?;
            Ok(Some(Zeroizing::new(slice)))
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(keyring::Error::NoStorageAccess(_)) => {
            Err("Der Schlüsselbund ist gesperrt.".into())
        }
        Err(e) => Err(format!("Schlüsselbund nicht lesbar: {e}")),
    }
}

/// Entfernt `K`. Alle darauf aufbauenden Siegel werden damit unbrauchbar.
#[cfg(not(target_os = "android"))]
pub fn clear() -> Result<(), String> {
    match entry()?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(format!("Schlüsselbund lässt den Wert nicht löschen: {e}")),
    }
}

#[cfg(not(target_os = "android"))]
fn entry() -> Result<keyring::Entry, String> {
    keyring::Entry::new(SERVICE, ACCOUNT)
        .map_err(|e| format!("Kein Schlüsselbund verfügbar: {e}"))
}

/* =========================================================
   Android — Datei im privaten Verzeichnis der App
   ========================================================= */

#[cfg(target_os = "android")]
mod android {
    use super::{Availability, Zeroizing};
    use tauri::Manager;

    /// Liegt unter `/data/data/de.wuefl.wkeepass/…`, ohne Root von außen
    /// unlesbar.
    fn path() -> Result<std::path::PathBuf, String> {
        let app = crate::app_handle().ok_or("Die Anwendung läuft noch nicht.")?;
        let dir = app
            .path()
            .app_local_data_dir()
            .map_err(|e| format!("Kein Datenverzeichnis: {e}"))?;
        Ok(dir.join("device-key.bin"))
    }

    pub fn availability() -> Availability {
        if path().is_ok() { Availability::Ready } else { Availability::Missing }
    }

    pub fn store(key: &[u8; 32]) -> Result<(), String> {
        let target = path()?;
        if let Some(dir) = target.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("Verzeichnis fehlt: {e}"))?;
        }
        std::fs::write(&target, key).map_err(|e| format!("Schlüssel nicht gespeichert: {e}"))?;

        // Nur für den Besitzer lesbar, zusätzlich zur Abschottung des
        // App-Verzeichnisses unter Android.
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600));
        Ok(())
    }

    pub fn load() -> Result<Option<Zeroizing<[u8; 32]>>, String> {
        let target = path()?;
        match std::fs::read(&target) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("Schlüssel nicht lesbar: {e}")),
            Ok(bytes) => {
                let key: [u8; 32] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| "Der gespeicherte Schlüssel hat die falsche Länge.".to_string())?;
                Ok(Some(Zeroizing::new(key)))
            }
        }
    }

    pub fn clear() -> Result<(), String> {
        match std::fs::remove_file(path()?) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("Schlüssel nicht gelöscht: {e}")),
        }
    }
}
