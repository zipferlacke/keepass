//! Der Zufallsschlüssel `K` im Schlüsselbund des Systems.
//!
//! `K` ist 32 Byte Zufall und wird nie angezeigt, nie exportiert und nie in
//! unsere eigenen Dateien geschrieben. Er ist die zweite Zutat neben der PIN
//! (siehe `seal.rs`) und die einzige Zutat, wenn per Fingerabdruck entsperrt
//! wird.
//!
//! # Warum überhaupt zwei Zutaten
//!
//! Ohne `K` läge unser Siegel offen: Wer die Datei hat, probiert die PIN
//! offline durch — eine sechsstellige PIN ist damit binnen Stunden auf.
//! Mit `K` braucht ein Angreifer **beides**, unsere Datei und deine
//! angemeldete Sitzung, und die PIN wird von der letzten Verteidigungslinie
//! zur zweiten.
//!
//! # Was der Schlüsselbund je nach System taugt
//!
//! ```text
//! macOS     Keychain, dahinter die Secure Enclave  — hardwaregebunden
//! Windows   Credential Manager, dahinter das TPM   — hardwaregebunden
//! Linux     Secret Service (gnome-keyring, ksecretd)
//!           → an dein Anmeldepasswort gebunden, die Datei ist offline
//!             angreifbar. Besser als nichts, aber kein Chip.
//! Android   kein Secret Service. `K` liegt hier in einer Datei im
//!           privaten Verzeichnis der App — für andere Anwendungen
//!           unlesbar, solange das Gerät nicht gerootet ist, aber **nicht**
//!           an einen Chip gebunden.
//!
//!           Für den Fingerabdruck braucht es `K` deshalb gar nicht: Dort
//!           gibt es seit dem Android-Keystore einen eigenen, wirklich
//!           hardwaregebundenen Weg (`biometric::device_key`), und der
//!           kommt ohne diese Datei und ohne PIN aus. `K` bleibt hier für
//!           den PIN-Weg.
//! ```
//!
//! Ein TPM unter x86-Linux könnte mehr — es würde Fehlversuche selbst
//! zählen und die PIN damit wirklich absichern. Das wäre der nächste
//! Ausbauschritt (`tss-esapi`), hier noch nicht drin.

use zeroize::Zeroizing;

const SERVICE: &str = "de.wuefl.wkeepass";
const ACCOUNT: &str = "master-key";

/// In welchem Zustand ist der Schlüsselbund?
///
/// Die drei Fälle sind wirklich verschieden und dürfen nicht zusammenfallen:
/// Ein gesperrter Schlüsselbund ist etwas anderes als gar keiner.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum Availability {
    /// Ein Dienst antwortet und gibt Werte heraus.
    Ready,
    /// Es gibt einen, aber er ist zu. Das passiert unter Linux, wenn man
    /// sich per Fingerabdruck oder automatisch anmeldet — dann bekommt der
    /// Dienst nie ein Passwort zum Entschlüsseln.
    Locked,
    /// Gar keiner da: minimale Installation, Android, oder kein Dienst
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
            // Kein Eintrag heißt: Der Speicher ist da, wir haben nur noch
            // nichts hineingelegt.
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

/// Holt `K` zurück. `None` heißt: Es liegt keiner dort.
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

/// Entfernt `K`. Damit wird jedes Siegel unbrauchbar, das darauf aufbaut.
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

    /// Liegt unter `/data/data/de.wuefl.wkeepass/…` — von außen unlesbar,
    /// solange das Gerät nicht gerootet ist.
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

        // Nur für uns lesbar. Auf Android ist das Verzeichnis ohnehin
        // abgeschottet; der Gürtel zum Hosenträger kostet nichts.
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
