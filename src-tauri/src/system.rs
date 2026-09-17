//! Anbindung an das Betriebssystem.

use tauri_plugin_dialog::DialogExt;

/// Öffnet den Dateidialog des Betriebssystems und gibt den Pfad zurück.
#[tauri::command]
pub async fn pick_database_file(app: tauri::AppHandle) -> Result<Option<String>, String> {
    let (tx, rx) = std::sync::mpsc::channel();

    app.dialog()
        .file()
        .add_filter("KeePass-Datenbank", &["kdbx"])
        .pick_file(move |path| {
            let _ = tx.send(path.map(|p| p.to_string()));
        });

    rx.recv().map_err(|e| format!("Dateiauswahl fehlgeschlagen: {e}"))
}

/// Fragt, wohin eine **neue** Datenbank geschrieben werden soll.
///
/// Der Dateiauswahldialog kann nur Vorhandenes zeigen; zum Anlegen braucht
/// es den Speichern-Dialog. Die Endung hängt der Aufrufer nicht selbst an —
/// das erledigt der Filter zusammen mit dem Vorschlag.
#[tauri::command]
pub async fn pick_save_path(
    app: tauri::AppHandle,
    suggested: String,
) -> Result<Option<String>, String> {
    let (tx, rx) = std::sync::mpsc::channel();

    app.dialog()
        .file()
        .add_filter("KeePass-Datenbank", &["kdbx"])
        .set_file_name(suggested)
        .save_file(move |path| {
            let _ = tx.send(path.map(|p| p.to_string()));
        });

    let picked = rx.recv().map_err(|e| format!("Speicherort-Auswahl fehlgeschlagen: {e}"))?;

    // Manche Dialoge geben den Namen ohne Endung zurück.
    Ok(picked.map(|p| if p.ends_with(".kdbx") { p } else { format!("{p}.kdbx") }))
}

/// Die Datenbank, mit der die Anwendung aufgerufen wurde.
///
/// Beim Doppelklick auf eine `.kdbx`-Datei startet das System die Anwendung
/// mit dem Pfad als Argument — das ist die andere Hälfte der Dateizuordnung
/// aus `tauri.conf.json`. Ohne diese Stelle ginge nur ein leeres Fenster auf.
///
/// Zurück kommt nur, was auch wirklich existiert und auf `.kdbx` endet.
/// Argumente sind nichts, worauf man blind vertrauen sollte, und ein Pfad,
/// der ins Leere zeigt, würde die Oberfläche bloß mit einem Fehler begrüßen.
///
/// Läuft bereits ein Fenster, bekommt es davon nichts mit — dann startet
/// eine zweite Ausgabe des Programms. Das über den Ersten zu leiten bräuchte
/// das Einzelinstanz-Plugin und ist noch nicht drin.
#[tauri::command]
pub fn startup_database() -> Option<String> {
    std::env::args()
        .skip(1)
        .find(|arg| {
            let path = std::path::Path::new(arg);
            path.extension().is_some_and(|e| e.eq_ignore_ascii_case("kdbx")) && path.is_file()
        })
        .and_then(|arg| {
            // Aufgelöst, damit auch ein relativer Aufruf aus der Kommandozeile
            // denselben Pfad ergibt wie der Doppelklick — sonst gälte dieselbe
            // Datenbank als zwei verschiedene.
            std::fs::canonicalize(&arg)
                .map(|p| p.to_string_lossy().to_string())
                .ok()
        })
}

/// Holt den Titel einer Website.
///
/// Aus dem Webview heraus geht das nicht — fremde Seiten verbieten den
/// Zugriff per CORS. Rust hat diese Einschränkung nicht.
#[tauri::command]
pub async fn fetch_page_title(url: String) -> Result<Option<String>, String> {
    let target = if url.starts_with("http") { url } else { format!("https://{url}") };

    // TODO: mit reqwest abrufen (Zeitlimit setzen, Weiterleitungen begrenzen,
    //       Antwortgröße deckeln) und <title> herausziehen. Wichtig: kein
    //       eigener User-Agent-Fingerabdruck, keine Cookies mitsenden.
    //       Solange das fehlt, nimmt die Oberfläche den Hostnamen.
    let _ = target;
    Ok(None)
}
