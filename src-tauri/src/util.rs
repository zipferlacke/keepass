//! Kleinkram, den mehrere Module brauchen.

use std::io::Write;
use std::path::Path;

/// Schreibt so, dass ein Abbruch die Datei nicht zerstören kann:
/// Sicherungskopie, vollständig in eine Nebendatei, auf die Platte zwingen,
/// dann atomar umbenennen.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() {
        return Err("Es sollten 0 Bytes geschrieben werden — abgebrochen.".into());
    }

    let tmp = with_suffix(path, "tmp");

    if path.exists() {
        std::fs::copy(path, with_suffix(path, "bak"))
            .map_err(|e| format!("Sicherungskopie fehlgeschlagen: {e}"))?;
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Verzeichnis konnte nicht angelegt werden: {e}"))?;
    }

    {
        let mut file = std::fs::File::create(&tmp)
            .map_err(|e| format!("Nebendatei konnte nicht angelegt werden: {e}"))?;
        file.write_all(bytes).map_err(|e| format!("Schreiben fehlgeschlagen: {e}"))?;
        // Ohne sync_all liegen die Daten eventuell noch im Cache und das
        // Umbenennen zeigt auf eine leere Datei.
        file.sync_all().map_err(|e| format!("Synchronisieren fehlgeschlagen: {e}"))?;
    }

    std::fs::rename(&tmp, path).map_err(|e| format!("Umbenennen fehlgeschlagen: {e}"))
}

/// `passwords.kdbx` + `bak` → `passwords.kdbx.bak`
///
/// Anhängen statt `set_extension`, damit aus `passwords.kdbx` nicht
/// `passwords.bak` wird und zwei Datenbanken sich die Sicherungskopie teilen.
fn with_suffix(path: &Path, suffix: &str) -> std::path::PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".");
    name.push(suffix);
    name.into()
}
