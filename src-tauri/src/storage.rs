//! Dateien lesen und schreiben — auch dort, wo es keine Pfade gibt.
//!
//! # Warum das nötig ist
//!
//! Auf dem Schreibtisch ist eine Datei ein Pfad: `/home/du/passwoerter.kdbx`.
//! Auf Android nicht. Dort wählt der Nutzer die Datei in einer fremden
//! Anwendung aus (Dateien, Google Drive, Nextcloud), und heraus kommt eine
//! Adresse wie
//!
//! ```text
//! content://com.android.externalstorage.documents/document/primary%3ADocuments%2Fpasswoerter.kdbx
//! ```
//!
//! Dahinter steckt kein Ort im Dateisystem, sondern die Erlaubnis, genau
//! diese eine Datei über einen fremden Anbieter zu öffnen. `std::fs` kann
//! damit nichts anfangen; das Betriebssystem muss die Datei aufmachen und
//! uns die offene Datei reichen. Genau das macht das fs-Plugin von Tauri.
//!
//! Alles, was an Datenbanken und Anhängen gelesen oder geschrieben wird,
//! geht deshalb hier durch. Der übrige Kern kennt weiter nur Zeichenketten.
//!
//! # Was auf Android trotzdem anders bleibt
//!
//! * **Keine Sicherungskopie daneben.** Auf dem Schreibtisch schreibt
//!   `write_atomic` erst eine Nebendatei und benennt um. Über eine
//!   `content://`-Adresse geht das nicht: Wir dürfen die eine Datei
//!   anfassen, nicht das Verzeichnis. Die Offline-Kopie in `offline.rs`
//!   federt das ab.
//! * **Die Erlaubnis kann ablaufen.** Sie gilt für die Sitzung; nach einem
//!   Neustart der App kann dieselbe Adresse ins Leere zeigen. Dann bleibt
//!   die Offline-Kopie zum Lesen, und zum Speichern muss die Datei erneut
//!   ausgewählt werden.

/// Merkt sich die Erlaubnis für diese Datei dauerhaft.
///
/// Android gibt beim Auswählen nur eine Erlaubnis für den Augenblick. Nach
/// dem nächsten Start der App zeigt dieselbe Adresse ins Leere — dann bliebe
/// nur die Offline-Kopie. `takePersistableUriPermission` hebt das auf: Die
/// Erlaubnis überlebt Neustarts, bis der Nutzer sie entzieht.
///
/// Fehlschläge sind kein Grund abzubrechen: Öffnen geht auch ohne, nur eben
/// nur dieses eine Mal.
pub fn remember_access(path: &str) {
    if is_uri(path) {
        uri::remember(path);
    }
}

/// Ist das eine Adresse statt eines Pfads?
pub fn is_uri(path: &str) -> bool {
    path.starts_with("content://")
}

/// Liest eine Datei — Pfad oder `content://`-Adresse.
pub fn read(path: &str) -> Result<Vec<u8>, String> {
    if is_uri(path) {
        return uri::read(path);
    }
    std::fs::read(path).map_err(|e| format!("Datei nicht lesbar: {e}"))
}

/// Schreibt eine Datei.
///
/// Über einen Pfad so, dass ein Abbruch die alte Fassung nicht zerstört
/// (siehe `util::write_atomic`). Über eine Adresse direkt — etwas anderes
/// lässt Android nicht zu.
pub fn write(path: &str, bytes: &[u8]) -> Result<(), String> {
    if is_uri(path) {
        return uri::write(path, bytes);
    }
    crate::util::write_atomic(std::path::Path::new(path), bytes)
}

/// Der Name ohne Verzeichnis — für die Anzeige.
///
/// Bei einer Adresse steht der Name nur manchmal drin: Der Dateispeicher
/// von Android schreibt ihn hinein (`primary%3ADownload%2Ftest.kdbx`),
/// Nextcloud und der Download-Anbieter nur eine Kennung. Dann ist die
/// Herkunft die beste Auskunft, die sich ohne Rückfrage beim Anbieter
/// herausholen lässt — den Rest liefert nach dem Öffnen der Name aus der
/// Datenbank selbst.
pub fn file_name(path: &str) -> String {
    if is_uri(path) {
        let last = path.rsplit(['/', ':']).next().unwrap_or(path);
        let decoded = last
            .replace("%2F", "/")
            .replace("%2f", "/")
            .replace("%3A", ":")
            .replace("%20", " ");
        let name = decoded.rsplit(['/', ':']).next().unwrap_or(&decoded);

        if name.contains('.') && !name.chars().all(|c| c.is_ascii_hexdigit()) {
            return name.to_string();
        }
        return format!("Datenbank in {}", herkunft(path));
    }
    std::path::Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| path.to_string())
}

/// Wie die Datei heißt und wo sie liegt — für die Anzeige, etwa
/// „Downloads — passwoerter.kdbx".
///
/// Auf dem Schreibtisch ist das schlicht der Pfad.
pub fn label(path: &str) -> String {
    if !is_uri(path) {
        return path.to_string();
    }

    // Beim Gerätespeicher steht der Ordner in der Adresse:
    // `…/document/primary%3ADownload%2Ftest.kdbx`.
    let aus_adresse = path
        .rsplit('/')
        .next()
        .map(|last| {
            last.replace("%3A", ":").replace("%2F", "/").replace("%20", " ")
        })
        .and_then(|id| id.split_once(':').map(|(_, rest)| rest.to_string()))
        .filter(|rest| rest.contains('.'));

    match (aus_adresse, uri::display_name(path)) {
        (Some(pfad), _) => format!("{}/{pfad}", herkunft(path)),
        (None, Some(name)) => format!("{}/{name}", herkunft(path)),
        (None, None) => herkunft(path),
    }
}

/// Welche Anwendung die Datei bereitstellt — aus der Adresse abgelesen.
pub fn herkunft(path: &str) -> String {
    let authority = path
        .trim_start_matches("content://")
        .split('/')
        .next()
        .unwrap_or_default();

    match authority {
        "com.android.providers.downloads.documents" => "Downloads".into(),
        "com.android.externalstorage.documents" => "Gerätespeicher".into(),
        "media" | "com.android.providers.media.documents" => "Medien".into(),
        "org.nextcloud.documents" => "Nextcloud".into(),
        "com.google.android.apps.docs.storage" => "Google Drive".into(),
        // `de.foo.bar.documents` → `bar`: besser als die ganze Kennung.
        other => other
            .trim_end_matches(".documents")
            .rsplit('.')
            .next()
            .unwrap_or("Android")
            .to_string(),
    }
}

/* =========================================================
   Android: über den ContentResolver
   ========================================================= */

#[cfg(target_os = "android")]
mod uri {
    use std::io::{Read, Write};

    use tauri_plugin_fs::{FilePath, FsExt, OpenOptions};

    fn oeffnen(path: &str, opts: OpenOptions) -> Result<std::fs::File, String> {
        let app = crate::app_handle().ok_or("Die Anwendung läuft noch nicht.")?;
        let uri: FilePath = path
            .parse()
            .map_err(|_| format!("Adresse nicht lesbar: {path}"))?;

        app.fs().open(uri, opts).map_err(|e| {
            // Ins Protokoll, weil die Meldung auf dem Bildschirm abgeschnitten
            // wird und genau hier die Ursache steht (`adb logcat`).
            eprintln!("[storage] {path} nicht zu öffnen: {e}");
            format!("Datei nicht erreichbar: {e}")
        })
    }

    /// `contentResolver.takePersistableUriPermission(uri, lesen | schreiben)`
    ///
    /// Über JNI, weil es dafür keine Rust-Schnittstelle gibt: Der Weg führt
    /// über die Activity, die uns tao bereitstellt.
    pub fn remember(path: &str) {
        use jni::objects::{JObject, JValue};
        use tao::platform::android::prelude::main_android_context;

        let Some(ctx) = main_android_context() else { return };

        let ergebnis = (|| -> Result<(), jni::errors::Error> {
            let vm = unsafe { jni::JavaVM::from_raw(ctx.java_vm.cast()) }?;
            let mut env = vm.attach_current_thread()?;
            let activity = unsafe { JObject::from_raw(ctx.context_jobject.cast()) };

            let resolver = env
                .call_method(
                    &activity,
                    "getContentResolver",
                    "()Landroid/content/ContentResolver;",
                    &[],
                )?
                .l()?;

            let text = env.new_string(path)?;
            let uri = env
                .call_static_method(
                    "android/net/Uri",
                    "parse",
                    "(Ljava/lang/String;)Landroid/net/Uri;",
                    &[JValue::Object(&text.into())],
                )?
                .l()?;

            // FLAG_GRANT_READ_URI_PERMISSION | FLAG_GRANT_WRITE_URI_PERMISSION
            let flags = 0x0000_0001 | 0x0000_0002;
            env.call_method(
                resolver,
                "takePersistableUriPermission",
                "(Landroid/net/Uri;I)V",
                &[JValue::Object(&uri), JValue::Int(flags)],
            )?;

            // Eine Ausnahme auf der Java-Seite muss abgeräumt werden, sonst
            // stolpert der nächste JNI-Aufruf darüber.
            if env.exception_check()? {
                env.exception_clear()?;
                return Err(jni::errors::Error::JavaException);
            }
            Ok(())
        })();

        if let Err(e) = ergebnis {
            eprintln!("[storage] Erlaubnis für {path} nicht dauerhaft: {e}");
        }
    }

    /// Fragt den Anbieter nach dem Anzeigenamen der Datei
    /// (`OpenableColumns.DISPLAY_NAME`).
    ///
    /// In der Adresse steht er meist nicht drin — Nextcloud und der
    /// Download-Speicher setzen dort eine Kennung. Wissen tut ihn nur der
    /// Anbieter selbst, und den fragt man über den ContentResolver.
    pub fn display_name(path: &str) -> Option<String> {
        use jni::objects::{JObject, JObjectArray, JString, JValue};
        use tao::platform::android::prelude::main_android_context;

        let ctx = main_android_context()?;

        let hole = || -> Result<Option<String>, jni::errors::Error> {
            let vm = unsafe { jni::JavaVM::from_raw(ctx.java_vm.cast()) }?;
            let mut env = vm.attach_current_thread()?;
            let activity = unsafe { JObject::from_raw(ctx.context_jobject.cast()) };

            let resolver = env
                .call_method(&activity, "getContentResolver", "()Landroid/content/ContentResolver;", &[])?
                .l()?;

            let text = env.new_string(path)?;
            let uri = env
                .call_static_method(
                    "android/net/Uri",
                    "parse",
                    "(Ljava/lang/String;)Landroid/net/Uri;",
                    &[JValue::Object(&text.into())],
                )?
                .l()?;

            let spalte = env.new_string("_display_name")?;
            let spalten: JObjectArray = env.new_object_array(1, "java/lang/String", &spalte)?;

            let cursor = env
                .call_method(
                    resolver,
                    "query",
                    "(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;",
                    &[
                        JValue::Object(&uri),
                        JValue::Object(&spalten),
                        JValue::Object(&JObject::null()),
                        JValue::Object(&JObject::null()),
                        JValue::Object(&JObject::null()),
                    ],
                )?
                .l()?;

            if cursor.is_null() {
                return Ok(None);
            }

            let mut name = None;
            if env.call_method(&cursor, "moveToFirst", "()Z", &[])?.z()? {
                let wert = env.call_method(&cursor, "getString", "(I)Ljava/lang/String;", &[JValue::Int(0)])?.l()?;
                if !wert.is_null() {
                    name = Some(env.get_string(&JString::from(wert))?.into());
                }
            }
            env.call_method(&cursor, "close", "()V", &[])?;
            Ok(name)
        };

        match hole() {
            Ok(name) => name,
            Err(e) => {
                eprintln!("[storage] Name zu {path} nicht ermittelbar: {e}");
                None
            }
        }
    }

    pub fn read(path: &str) -> Result<Vec<u8>, String> {
        let mut file = oeffnen(path, OpenOptions::new().read(true).clone())?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|e| format!("Datei nicht lesbar: {e}"))?;
        Ok(bytes)
    }

    pub fn write(path: &str, bytes: &[u8]) -> Result<(), String> {
        // Welche Betriebsart ein Anbieter annimmt, ist von Anbieter zu
        // Anbieter verschieden: Der Download-Speicher lehnt „wt" ab, andere
        // brauchen genau das, damit vom längeren alten Inhalt nichts
        // stehenbleibt. Deshalb der Reihe nach probieren.
        let modi = [
            OpenOptions::new().write(true).truncate(true).clone(),
            OpenOptions::new().read(true).write(true).truncate(true).clone(),
            OpenOptions::new().write(true).clone(),
            OpenOptions::new().read(true).write(true).clone(),
        ];

        let mut letzter = String::from("Datei nicht beschreibbar.");
        for modus in modi {
            match oeffnen(path, modus) {
                Err(e) => letzter = e,
                Ok(mut file) => {
                    file.write_all(bytes)
                        .map_err(|e| format!("Schreiben fehlgeschlagen: {e}"))?;
                    file.sync_all()
                        .map_err(|e| format!("Synchronisieren fehlgeschlagen: {e}"))?;
                    return Ok(());
                }
            }
        }
        Err(letzter)
    }
}

/// Außerhalb von Android gibt es keine `content://`-Adressen — die Zweige
/// oben laufen nie hier hinein.
#[cfg(not(target_os = "android"))]
mod uri {
    pub fn remember(_path: &str) {}

    pub fn display_name(_path: &str) -> Option<String> {
        None
    }

    pub fn read(path: &str) -> Result<Vec<u8>, String> {
        Err(format!("Adressen dieser Art gibt es hier nicht: {path}"))
    }

    pub fn write(path: &str, _bytes: &[u8]) -> Result<(), String> {
        Err(format!("Adressen dieser Art gibt es hier nicht: {path}"))
    }
}
