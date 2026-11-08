//! Alle Bilder liegen in appdata/. Die Oberfläche (frontendDist = src-ui) braucht
//! das Logo daneben und bekommt es vor dem Einbetten hierher kopiert. Die Kopien
//! stehen nicht im Repository (.gitignore).
//!
//! Auch die Kopie wird beobachtet, damit das Skript bei fehlender Kopie neu läuft.
//! Sie erhält die Zeit der Quelle, damit Cargo sie nicht bei jedem Lauf für
//! geändert hält.

use std::path::Path;

const BILDER: [&str; 2] = ["logo.svg", "logo.png"];

fn main() {
    let appdata = Path::new("../appdata");
    let ui = Path::new("../src-ui");
    for name in BILDER {
        let quelle = appdata.join(name);
        let ziel = ui.join(name);
        println!("cargo:rerun-if-changed={}", quelle.display());
        println!("cargo:rerun-if-changed={}", ziel.display());
        if std::fs::read(&quelle).ok() != std::fs::read(&ziel).ok() {
            std::fs::copy(&quelle, &ziel).unwrap_or_else(|e| panic!("{} kopieren: {e}", quelle.display()));
            let zeit = std::fs::metadata(&quelle).and_then(|m| m.modified());
            if let (Ok(zeit), Ok(datei)) = (zeit, std::fs::File::options().write(true).open(&ziel)) {
                let _ = datei.set_modified(zeit);
            }
        }
    }
    tauri_build::build()
}
