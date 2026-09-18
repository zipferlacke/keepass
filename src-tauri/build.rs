//! Alle Bilder liegen in appdata/. Die Oberfläche (frontendDist = src-ui)
//! braucht das Logo aber neben sich — also vor dem Einbetten hinüberkopieren.
//! Die Kopien stehen nicht im Repository (.gitignore).

use std::path::Path;

const BILDER: [&str; 2] = ["logo.svg", "logo.png"];

fn main() {
    let appdata = Path::new("../appdata");
    let ui = Path::new("../src-ui");
    for name in BILDER {
        let quelle = appdata.join(name);
        println!("cargo:rerun-if-changed={}", quelle.display());
        let ziel = ui.join(name);
        if std::fs::read(&quelle).ok() != std::fs::read(&ziel).ok() {
            std::fs::copy(&quelle, &ziel).unwrap_or_else(|e| panic!("{} kopieren: {e}", quelle.display()));
        }
    }
    tauri_build::build()
}
