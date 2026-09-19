//! Alle Bilder liegen in appdata/. Die Oberfläche (frontendDist = src-ui)
//! braucht das Logo aber neben sich — also vor dem Einbetten hinüberkopieren.
//! Die Kopien stehen nicht im Repository (.gitignore).
//!
//! Beobachtet wird auch die Kopie: Fehlt sie (etwa nach einem Aufräumen der
//! ignorierten Dateien), läuft das Skript neu, statt die Oberfläche ohne
//! Logo einzubetten. Die Kopie bekommt die Zeit der Quelle, sonst hielte
//! Cargo sie bei jedem Lauf für frisch geändert und baute alles neu.

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
