//! Zwischengespeicherte Kopie jeder geöffneten Datenbank.
//!
//! Die Datei liegt oft dort, wo sie nicht immer erreichbar ist: auf einem
//! Netzlaufwerk, einem USB-Stick, in einem Ordner, den die Synchronisierung
//! gerade umschreibt. Damit die Passwörter trotzdem da sind, legt der Kern
//! nach jedem erfolgreichen Öffnen und Speichern eine Kopie ins eigene
//! Datenverzeichnis.
//!
//! Die Kopie ist die Datei **wie sie auf der Platte lag** — verschlüsselt,
//! mit demselben Master-Passwort. Klartext landet dabei nirgends.
//!
//! Ist der Ort beim nächsten Öffnen nicht lesbar, wird die Kopie geöffnet.
//! Speichern geht dann erst wieder, wenn die Datei zurück ist und sich
//! inzwischen nicht verändert hat (siehe `database::commit`).

use std::path::{Path, PathBuf};

use tauri::Manager;

/// Woher die geöffneten Bytes stammen.
pub enum Source {
    /// Vom eigentlichen Ort.
    Original,
    /// Aus der Kopie, weil der Ort nicht lesbar war. Mit dem Zeitpunkt der
    /// Kopie (RFC 3339) und dem Grund.
    Cached { saved_at: String, reason: String },
}

/// Liest die Datenbank vom Ort — oder, wenn das scheitert, aus der Kopie.
pub fn read(app: &tauri::AppHandle, path: &str) -> Result<(Vec<u8>, Source), String> {
    match std::fs::read(path) {
        Ok(raw) => Ok((raw, Source::Original)),
        Err(err) => {
            let reason = format!("Datei nicht lesbar: {err}");
            let Some(copy) = copy_path(app, path).filter(|p| p.is_file()) else {
                return Err(reason);
            };
            let raw = std::fs::read(&copy).map_err(|_| reason.clone())?;
            let saved_at = std::fs::metadata(&copy)
                .and_then(|m| m.modified())
                .map(|t| chrono::DateTime::<chrono::Local>::from(t).to_rfc3339())
                .unwrap_or_default();
            Ok((raw, Source::Cached { saved_at, reason }))
        }
    }
}

/// Legt die Kopie ab oder erneuert sie. Fehler werden nur gemeldet, nicht
/// weitergereicht: Ohne Kopie geht alles weiter wie bisher.
pub fn store(app: &tauri::AppHandle, path: &str, bytes: &[u8]) {
    let Some(copy) = copy_path(app, path) else { return };

    if std::fs::read(&copy).is_ok_and(|old| old == bytes) {
        return;
    }
    if let Err(err) = write(&copy, bytes) {
        eprintln!("Offline-Kopie nicht gespeichert: {err}");
    }
}

/// `<Datenverzeichnis>/offline/<SHA-256 des Pfads>.kdbx`
///
/// Gehasht, damit Pfade mit Schrägstrichen und Sonderzeichen einen
/// gültigen Dateinamen ergeben und zwei gleichnamige Dateien aus
/// verschiedenen Ordnern sich nicht überschreiben.
fn copy_path(app: &tauri::AppHandle, path: &str) -> Option<PathBuf> {
    use sha2::{Digest, Sha256};

    let hash = Sha256::digest(path.as_bytes());
    let name: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    let dir = app.path().app_local_data_dir().ok()?.join("offline");
    Some(dir.join(format!("{name}.kdbx")))
}

/// Nebendatei schreiben und umbenennen — eine halbe Kopie wäre schlimmer
/// als keine. Eine Sicherungskopie wie bei `write_atomic` braucht es nicht.
fn write(target: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;

    if let Some(dir) = target.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let tmp = target.with_extension("kdbx.tmp");
    {
        let mut file = std::fs::File::create(&tmp).map_err(|e| e.to_string())?;
        file.write_all(bytes).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
    }
    std::fs::rename(&tmp, target).map_err(|e| e.to_string())
}
