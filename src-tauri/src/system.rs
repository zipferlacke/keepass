//! Anbindung an das Betriebssystem.

use tauri_plugin_dialog::DialogExt;

/// Öffnet den Dateidialog des Betriebssystems und gibt den Pfad zurück.
#[tauri::command]
pub async fn pick_database_file(app: tauri::AppHandle) -> Result<Option<String>, String> {
    // Android: eigene Auswahl über ACTION_OPEN_DOCUMENT. Der Tauri-Dialog
    // nimmt ACTION_GET_CONTENT, und dessen Erlaubnis endet mit der App —
    // eine Datei aus Nextcloud war nach dem Neustart nicht mehr lesbar.
    #[cfg(target_os = "android")]
    {
        let _ = &app;
        return tauri::async_runtime::spawn_blocking(dateiwahl)
            .await
            .map_err(|e| e.to_string())?;
    }

    #[cfg(not(target_os = "android"))]
    let (tx, rx) = std::sync::mpsc::channel();

    #[cfg(not(target_os = "android"))]
    {
        app.dialog()
            .file()
            .add_filter("KeePass-Datenbank", &["kdbx"])
            .pick_file(move |path| {
                let _ = tx.send(path.map(|p| p.to_string()));
            });

        let picked = rx.recv().map_err(|e| format!("Dateiauswahl fehlgeschlagen: {e}"))?;

        // Ohne das wäre die Datei nach dem nächsten Start der App nicht mehr
        // erreichbar — siehe storage::remember_access.
        if let Some(path) = &picked {
            crate::storage::remember_access(path);
        }
        Ok(picked)
    }
}

/// Ruft `Dateiwahl.waehlen(activity)` und wartet auf die Wahl.
#[cfg(target_os = "android")]
fn dateiwahl() -> Result<Option<String>, String> {
    use jni::objects::{JString, JValue};

    crate::java::mit_java(|env, activity| {
        let klasse = crate::java::klasse(env, activity, "de.wuefl.wkeepass.system.Dateiwahl")?;
        let wert = env
            .call_static_method(&klasse, "waehlen", "(Landroid/app/Activity;)Ljava/lang/String;", &[JValue::Object(activity)])?
            .l()?;
        if wert.is_null() {
            return Ok(None);
        }
        Ok(Some(env.get_string(&JString::from(wert))?.into()))
    })
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

    // Manche Dialoge geben den Namen ohne Endung zurück — aber nur bei
    // echten Pfaden. Auf Android kommt eine Adresse
    // (`…/document/1500`), und die ist eine Kennung, kein Name: Hängt man
    // dort etwas an, zeigt sie auf nichts mehr, und Android verweigert das
    // Schreiben mit „Permission Denial".
    if let Some(path) = &picked {
        crate::storage::remember_access(path);
    }

    Ok(picked.map(|p| {
        if crate::storage::is_uri(&p) || p.ends_with(".kdbx") {
            p
        } else {
            format!("{p}.kdbx")
        }
    }))
}

/// Wie eine Datei in der Oberfläche heißen soll.
///
/// Auf dem Schreibtisch der Pfad, auf Android „Downloads — datei.kdbx": Den
/// Namen kennt dort nur der Anbieter der Datei, nicht die Adresse.
#[tauri::command]
pub fn path_label(path: String) -> String {
    crate::storage::label(&path)
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
/// Läuft bereits ein Fenster, startet das System eine zweite Ausgabe. Die
/// reicht ihre Argumente über das Einzelinstanz-Plugin an die laufende
/// weiter und beendet sich (`datei_uebergeben`).
#[tauri::command]
pub fn startup_database() -> Option<String> {
    // macOS meldet die Datei als Ereignis, womöglich bevor die Oberfläche
    // steht — dann liegt sie hier bereit.
    if let Some(path) = UEBERGEBEN.lock().ok().and_then(|mut p| p.take()) {
        return Some(path);
    }
    kdbx_aus(std::env::args().skip(1))
}

/// Die erste vorhandene `.kdbx` unter `args`, als vollständiger Pfad.
fn kdbx_aus(args: impl IntoIterator<Item = String>) -> Option<String> {
    args.into_iter()
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

/// Eine per Doppelklick übergebene Datei, bis die Oberfläche sie abholt.
static UEBERGEBEN: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Eine Datei soll geöffnet werden, während die App schon läuft: zweite
/// Ausgabe (Windows, Linux) oder Ereignis des Systems (macOS).
///
/// Die Oberfläche bekommt `open-database` und zeigt den Sperrbildschirm
/// dafür; das Fenster kommt nach vorn.
#[cfg(not(target_os = "android"))]
pub fn datei_uebergeben(app: &tauri::AppHandle, args: impl IntoIterator<Item = String>) {
    use tauri::{Emitter, Manager};

    #[cfg(desktop)]
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
    let Some(path) = kdbx_aus(args) else { return };
    if let Ok(mut p) = UEBERGEBEN.lock() {
        *p = Some(path.clone());
    }
    let _ = app.emit("open-database", path);
}

/// Wann die Datenbankdatei zuletzt geändert wurde (ms seit 1970) — für die
/// Einstellungen. `None`, wenn der Speicherort es nicht verrät.
#[tauri::command]
pub async fn database_modified(path: String) -> Result<Option<i64>, String> {
    tauri::async_runtime::spawn_blocking(move || crate::storage::modified_ms(&path))
        .await
        .map_err(|e| e.to_string())
}

/// Holt den Namen des Dienstes hinter einer Adresse (siehe `web::dienstname`).
///
/// Aus dem Webview heraus geht das nicht — fremde Seiten verbieten den
/// Zugriff per CORS. Rust hat diese Einschränkung nicht.
#[tauri::command]
pub async fn fetch_page_title(url: String) -> Result<Option<String>, String> {
    let target = if url.starts_with("http") { url } else { format!("https://{url}") };

    // Zeitlimit, Weiterleitungen und Größe regelt web.rs; Cookies gehen nie mit.
    tauri::async_runtime::spawn_blocking(move || {
        let seite = crate::web::get(&target, 512 * 1024).map_err(|e| e.to_string())?;
        Ok(crate::web::dienstname(&String::from_utf8_lossy(&seite.body), &seite.url))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Was auf Android eingerichtet ist: Autofill, Passkeys, Kamera.
///
/// `{ autofill: {moeglich, aktiv}, passkeys: {…}, kamera: {…, gesperrt} }`,
/// auf anderen Systemen `null` — dort gibt es nichts davon einzurichten.
#[tauri::command]
pub async fn android_setup_status() -> Result<serde_json::Value, String> {
    #[cfg(target_os = "android")]
    {
        let text = tauri::async_runtime::spawn_blocking(|| einrichtung("status", None))
            .await
            .map_err(|e| e.to_string())??;
        return serde_json::from_str(&text).map_err(|e| e.to_string());
    }
    #[cfg(not(target_os = "android"))]
    Ok(serde_json::Value::Null)
}

/// Springt in die Systemeinstellung für `what`: `autofill`, `passkeys`,
/// `kamera` (fragt die Berechtigung an) oder `app`.
#[tauri::command]
pub async fn android_setup_open(what: String) -> Result<bool, String> {
    #[cfg(target_os = "android")]
    {
        let text = tauri::async_runtime::spawn_blocking(move || einrichtung("oeffnen", Some(&what)))
            .await
            .map_err(|e| e.to_string())??;
        return Ok(text == "true");
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = what;
        Ok(false)
    }
}

/// Ruft `Einrichtung.status(activity)` bzw. `Einrichtung.oeffnen(activity, was)`.
#[cfg(target_os = "android")]
fn einrichtung(methode: &str, was: Option<&str>) -> Result<String, String> {
    use jni::objects::{JString, JValue};

    crate::java::mit_java(|env, activity| {
        let klasse = crate::java::klasse(env, activity, "de.wuefl.wkeepass.system.Einrichtung")?;
        match was {
            None => {
                let text = env
                    .call_static_method(&klasse, methode, "(Landroid/app/Activity;)Ljava/lang/String;", &[JValue::Object(activity)])?
                    .l()?;
                Ok(env.get_string(&JString::from(text))?.into())
            }
            Some(was) => {
                let was = env.new_string(was)?;
                let ok = env
                    .call_static_method(
                        &klasse,
                        methode,
                        "(Landroid/app/Activity;Ljava/lang/String;)Z",
                        &[JValue::Object(activity), JValue::Object(&was.into())],
                    )?
                    .z()?;
                Ok(ok.to_string())
            }
        }
    })
}

/// Öffnet eine Webadresse im Browser des Systems.
///
/// Bewusst nur `http` und `https`: Eine Adresse kommt hier aus Einträgen und
/// aus einer Liste aus dem Netz. `file:`, `intent:` oder ein eigenes Schema
/// könnten sonst Programme starten statt Seiten zeigen.
#[tauri::command]
pub fn open_link(app: tauri::AppHandle, url: String) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;

    let lower = url.trim().to_ascii_lowercase();
    if !(lower.starts_with("https://") || lower.starts_with("http://")) {
        return Err("Nur Webadressen lassen sich öffnen.".into());
    }
    app.opener()
        .open_url(url.trim(), None::<&str>)
        .map_err(|e| format!("Adresse nicht geöffnet: {e}"))
}
