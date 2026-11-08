#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // Dieselbe ausführbare Datei hat zwei Rollen. Startet der Browser sie über Native
    // Messaging, vermittelt sie nur Bytes zwischen ihm und der laufenden Anwendung,
    // ohne Fenster, Datenbank und GTK; das erkennt sie an den Argumenten des Browsers.
    // Die Prüfung steht vor `run()`, das ein Fenster öffnen würde.
    if wkeepass_lib::started_by_browser() {
        wkeepass_lib::run_proxy();
        return;
    }

    wkeepass_lib::run();
}
