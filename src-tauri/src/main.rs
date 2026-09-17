#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // Dieselbe ausführbare Datei bedient zwei ganz verschiedene Rollen.
    //
    // Startet der Browser uns über Native Messaging, sollen wir nur Bytes
    // zwischen ihm und der laufenden Anwendung schaufeln — kein Fenster,
    // keine Datenbank, kein GTK. Das erkennen wir an den Argumenten, die
    // ein Browser mitgibt und sonst nie auftauchen.
    //
    // Die Reihenfolge ist wichtig: `run()` würde ein Fenster öffnen, und
    // der Browser bekäme statt Antworten ein hängendes Programm.
    if wkeepass_lib::started_by_browser() {
        wkeepass_lib::run_proxy();
        return;
    }

    wkeepass_lib::run();
}
