//! `settings.json` an der plattformüblichen Stelle.
//!
//! Unter Linux ist das `~/.config/de.wuefl.wkeepass/settings.json`. Die
//! Standardwerte stehen nicht hier, sondern in `ui/config/settings.default.json`
//! — der Kern speichert nur, was die Oberfläche ihm gibt.

use std::path::PathBuf;

use tauri::Manager;

use crate::util::write_atomic;

fn settings_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_config_dir()
        .map_err(|e| format!("Kein Konfigurationsverzeichnis: {e}"))?;
    Ok(dir.join("settings.json"))
}

/// Liefert die gespeicherten Einstellungen — oder nichts, wenn es noch keine
/// gibt. Dann nimmt die Oberfläche ihre Standardwerte.
#[tauri::command]
pub fn settings_read(app: tauri::AppHandle) -> Result<Option<serde_json::Value>, String> {
    let path = settings_path(&app)?;

    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("settings.json nicht lesbar: {e}")),
    };

    // Eine beschädigte Datei darf den Start nicht verhindern — dann eben
    // Standardwerte, und beim nächsten Schreiben ist sie wieder in Ordnung.
    Ok(serde_json::from_str(&raw).ok())
}

/// Liest einen einzelnen Wert — für Stellen im Kern, die nicht auf die
/// Oberfläche warten können.
///
/// Der Weg über die Datei statt über einen gemerkten Zustand ist Absicht:
/// Die Browser-Anbindung läuft in eigenen Fäden, teils bevor ein Fenster
/// steht. Ein Fehlgriff kostet hier nichts — dann gilt die Voreinstellung.
pub fn value(app: &tauri::AppHandle, pfad: &str) -> Option<serde_json::Value> {
    let raw = std::fs::read_to_string(settings_path(app).ok()?).ok()?;
    let mut node: serde_json::Value = serde_json::from_str(&raw).ok()?;

    for teil in pfad.split('.') {
        node = node.get(teil)?.clone();
    }
    Some(node)
}

#[tauri::command]
pub fn settings_write(app: tauri::AppHandle, json: String) -> Result<bool, String> {
    if serde_json::from_str::<serde_json::Value>(&json).is_err() {
        return Err("Das war kein gültiges JSON.".into());
    }

    write_atomic(&settings_path(&app)?, json.as_bytes())?;
    Ok(true)
}
