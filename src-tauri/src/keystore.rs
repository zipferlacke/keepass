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
//! Android   eigener Keystore, läuft nicht über diese Schnittstelle
//!           → hier vorerst „kein Speicher", der Kern fällt auf die PIN
//!             zurück. Nachzurüsten über keyring-core mit
//!             android-native-keyring-store plus BiometricPrompt.
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
pub fn store(key: &[u8; 32]) -> Result<(), String> {
    entry()?
        .set_secret(key)
        .map_err(|e| format!("Schlüsselbund nimmt den Wert nicht an: {e}"))
}

/// Holt `K` zurück. `None` heißt: Es liegt keiner dort.
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
pub fn clear() -> Result<(), String> {
    match entry()?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(format!("Schlüsselbund lässt den Wert nicht löschen: {e}")),
    }
}

fn entry() -> Result<keyring::Entry, String> {
    keyring::Entry::new(SERVICE, ACCOUNT)
        .map_err(|e| format!("Kein Schlüsselbund verfügbar: {e}"))
}
