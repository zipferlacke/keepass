//! Dateien lesen und schreiben, auch für Android-`content://`-Adressen.
//!
//! Auf dem Schreibtisch ist eine Datei ein Pfad. Auf Android liefert die
//! Dateiauswahl eine Adresse wie
//!
//! ```text
//! content://com.android.externalstorage.documents/document/primary%3ADocuments%2Fpasswoerter.kdbx
//! ```
//!
//! Sie bezeichnet keine Stelle im Dateisystem, sondern die Erlaubnis, genau
//! diese Datei über einen Anbieter (Dateien, Google Drive, Nextcloud) zu
//! öffnen. Das übernimmt das fs-Plugin von Tauri über das Betriebssystem.
//! Alle Lese- und Schreibzugriffe auf Datenbanken und Anhänge laufen über
//! dieses Modul; der übrige Kern arbeitet mit Zeichenketten.
//!
//! # Einschränkungen unter Android
//!
//! * Keine Sicherungskopie neben der Datei: `write_atomic` schreibt auf dem
//!   Schreibtisch erst eine Nebendatei und benennt um. Über eine
//!   `content://`-Adresse ist nur die eine Datei zugänglich, nicht das
//!   Verzeichnis. Die Offline-Kopie (`offline.rs`) gleicht das aus.
//! * Die Erlaubnis gilt zunächst nur für die Sitzung. Nach einem Neustart
//!   kann dieselbe Adresse ins Leere zeigen; die Offline-Kopie bleibt dann
//!   lesbar, zum Speichern muss die Datei erneut ausgewählt werden.

/// Macht die Erlaubnis für diese Datei dauerhaft.
///
/// Android erteilt bei der Auswahl zunächst nur eine kurzzeitige Erlaubnis.
/// `takePersistableUriPermission` erhält sie über Neustarts, bis der Nutzer
/// sie entzieht. Schlägt das fehl, wird trotzdem geöffnet; die Erlaubnis gilt
/// dann nur für diese Sitzung.
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

/// Gibt es die Datei?
///
/// Eine `content://`-Adresse gilt immer als vorhanden: Ein Anbieter, der sie
/// nicht herausgibt, ist meist nur nicht erreichbar, die Datei nicht
/// gelöscht. Die Prüfung dient dazu, ein Überschreiben zu erkennen.
pub fn exists(path: &str) -> bool {
    is_uri(path) || std::path::Path::new(path).exists()
}

/// Wann die Datei zuletzt geändert wurde, in Millisekunden seit 1970.
///
/// Bei einer Adresse weiß das nur der Anbieter (Nextcloud, Drive …) —
/// `None`, wenn er es nicht verrät.
pub fn modified_ms(path: &str) -> Option<i64> {
    if is_uri(path) {
        return uri::modified_ms(path);
    }
    let zeit = std::fs::metadata(path).ok()?.modified().ok()?;
    Some(zeit.duration_since(std::time::UNIX_EPOCH).ok()?.as_millis() as i64)
}

/// Schreibt eine Datei.
///
/// Über einen Pfad atomar (siehe `util::write_atomic`), über eine Adresse
/// direkt, da Android nichts anderes zulässt.
pub fn write(path: &str, bytes: &[u8]) -> Result<(), String> {
    if is_uri(path) {
        return uri::write(path, bytes);
    }
    crate::util::write_atomic(std::path::Path::new(path), bytes)
}

/// Der Dateiname ohne Verzeichnis, für die Anzeige.
///
/// In einer Adresse steht der Name nur teilweise: Der Dateispeicher von
/// Android enthält ihn (`primary%3ADownload%2Ftest.kdbx`), Nextcloud und der
/// Download-Anbieter nur eine Kennung. Dann wird die Herkunft angezeigt; der
/// Name aus der Datenbank selbst steht nach dem Öffnen zur Verfügung.
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

/// Dateiname und Ablageort für die Anzeige, etwa „Downloads — passwoerter.kdbx".
/// Bei einem Pfad ist das der Pfad selbst.
pub fn label(path: &str) -> String {
    if !is_uri(path) {
        return path.to_string();
    }

    // Beim Gerätespeicher steht der Ordner in der Adresse,
    // z. B. `…/document/primary%3ADownload%2Ftest.kdbx`.
    let aus_adresse = path
        .rsplit('/')
        .next()
        .map(|last| {
            last.replace("%3A", ":").replace("%2F", "/").replace("%20", " ")
        })
        .and_then(|id| id.split_once(':').map(|(_, rest)| rest.to_string()))
        // Der Download-Anbieter liefert `raw:` mit dem ganzen Pfad
        // (`raw:/storage/emulated/0/Download/x.kdbx`); angezeigt wird der
        // Teil hinter dem Download-Ordner.
        .map(|rest| match rest.strip_prefix('/') {
            Some(voll) => voll
                .split_once("/Download/")
                .map(|(_, hinten)| hinten.to_string())
                .unwrap_or_else(|| voll.rsplit('/').next().unwrap_or(voll).to_string()),
            None => rest,
        })
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
        // `de.foo.bar.documents` → `bar`
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

    /// `contentResolver.openFileDescriptor(uri, modus)`; der Dateideskriptor
    /// wird als gewöhnliche `File` an Rust übergeben.
    ///
    /// Nicht über `tauri-plugin-fs`, das auf dem Hauptfaden öffnet: Anbieter
    /// wie Nextcloud holen die Datei dabei aus dem Netz, was Android auf dem
    /// Hauptfaden verbietet (`NetworkOnMainThreadException`). Der Aufruf läuft
    /// auf dem Arbeitsfaden.
    ///
    /// `modus` wie bei Android: `r`, `w`, `wt`, `rw`, `rwt`.
    fn oeffnen(path: &str, modus: &str) -> Result<std::fs::File, String> {
        use std::os::fd::FromRawFd;

        // Immer in einem eigenen Faden, da synchrone Tauri-Befehle (etwa
        // Speichern) auf dem Hauptfaden laufen.
        let (path_owned, modus_owned) = (path.to_string(), modus.to_string());
        let fd = std::thread::spawn(move || oeffnen_im_faden(&path_owned, &modus_owned))
            .join()
            .map_err(|_| "Öffnen abgestürzt.".to_string())??;

        if fd < 0 {
            return Err("Der Anbieter hat die Datei nicht herausgegeben.".into());
        }
        Ok(unsafe { std::fs::File::from_raw_fd(fd) })
    }

    fn oeffnen_im_faden(path: &str, modus: &str) -> Result<i32, String> {
        use jni::objects::JValue;

        crate::java::mit_java(|env, activity| {
            let resolver = env
                .call_method(activity, "getContentResolver", "()Landroid/content/ContentResolver;", &[])?
                .l()?;
            let uri = parse_uri(env, path)?;
            let modus = env.new_string(modus)?;
            let pfd = env
                .call_method(
                    resolver,
                    "openFileDescriptor",
                    "(Landroid/net/Uri;Ljava/lang/String;)Landroid/os/ParcelFileDescriptor;",
                    &[JValue::Object(&uri), JValue::Object(&modus.into())],
                )?
                .l()?;
            if pfd.is_null() {
                return Ok(-1);
            }
            // `detachFd`: Der Deskriptor gehört nun uns, `File` schließt ihn.
            // Beim Schließen lädt Nextcloud die Datei hoch.
            env.call_method(&pfd, "detachFd", "()I", &[])?.i()
        })
        .map_err(|e| {
            // Ins Protokoll (`adb logcat`), da die Bildschirmmeldung gekürzt wird.
            eprintln!("[storage] {path} nicht zu öffnen ({modus}): {e}");
            format!("Datei nicht erreichbar: {e}")
        })
    }

    /// `contentResolver.takePersistableUriPermission(uri, lesen | schreiben)`
    ///
    /// Über JNI, da es dafür keine Rust-Schnittstelle gibt. Funktioniert nur
    /// bei Dateien aus `ACTION_OPEN_DOCUMENT` oder `ACTION_CREATE_DOCUMENT`;
    /// bei anderen wirft Android eine `SecurityException`. Diese gilt nicht
    /// als Fehler, sondern wird protokolliert und von `mit_java` abgefangen.
    pub fn remember(path: &str) {
        use jni::objects::JValue;

        let ergebnis = crate::java::mit_java(|env, activity| {
            let resolver = env
                .call_method(activity, "getContentResolver", "()Landroid/content/ContentResolver;", &[])?
                .l()?;
            let uri = parse_uri(env, path)?;

            // FLAG_GRANT_READ_URI_PERMISSION | FLAG_GRANT_WRITE_URI_PERMISSION
            let flags = 0x0000_0001 | 0x0000_0002;
            env.call_method(
                resolver,
                "takePersistableUriPermission",
                "(Landroid/net/Uri;I)V",
                &[JValue::Object(&uri), JValue::Int(flags)],
            )?;
            Ok(())
        });

        if let Err(e) = ergebnis {
            eprintln!("[storage] Erlaubnis für {path} nicht dauerhaft: {e}");
        }
    }

    /// Fragt den Anbieter nach dem Anzeigenamen der Datei
    /// (`OpenableColumns.DISPLAY_NAME`).
    ///
    /// In der Adresse steht der Name meist nicht; Nextcloud und der
    /// Download-Speicher setzen dort eine Kennung.
    pub fn display_name(path: &str) -> Option<String> {
        use jni::objects::{JObject, JObjectArray, JString, JValue};

        let ergebnis = crate::java::mit_java(|env, activity| {
            let resolver = env
                .call_method(activity, "getContentResolver", "()Landroid/content/ContentResolver;", &[])?
                .l()?;
            let uri = parse_uri(env, path)?;

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
        });

        match ergebnis {
            Ok(name) => name,
            Err(e) => {
                eprintln!("[storage] Name zu {path} nicht ermittelbar: {e}");
                None
            }
        }
    }

    /// `DocumentsContract.Document.COLUMN_LAST_MODIFIED` beim Anbieter.
    pub fn modified_ms(path: &str) -> Option<i64> {
        use jni::objects::{JObject, JObjectArray, JValue};

        let ergebnis = crate::java::mit_java(|env, activity| {
            let resolver = env
                .call_method(activity, "getContentResolver", "()Landroid/content/ContentResolver;", &[])?
                .l()?;
            let uri = parse_uri(env, path)?;

            let spalte = env.new_string("last_modified")?;
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

            let mut zeit = None;
            if env.call_method(&cursor, "moveToFirst", "()Z", &[])?.z()?
                && !env.call_method(&cursor, "isNull", "(I)Z", &[JValue::Int(0)])?.z()?
            {
                let ms = env.call_method(&cursor, "getLong", "(I)J", &[JValue::Int(0)])?.j()?;
                if ms > 0 {
                    zeit = Some(ms);
                }
            }
            env.call_method(&cursor, "close", "()V", &[])?;
            Ok(zeit)
        });

        match ergebnis {
            Ok(zeit) => zeit,
            Err(e) => {
                eprintln!("[storage] Änderungszeit zu {path} nicht ermittelbar: {e}");
                None
            }
        }
    }

    fn parse_uri<'a>(env: &mut jni::JNIEnv<'a>, path: &str) -> Result<jni::objects::JObject<'a>, jni::errors::Error> {
        use jni::objects::JValue;
        let text = env.new_string(path)?;
        env.call_static_method(
            "android/net/Uri",
            "parse",
            "(Ljava/lang/String;)Landroid/net/Uri;",
            &[JValue::Object(&text.into())],
        )?
        .l()
    }

    pub fn read(path: &str) -> Result<Vec<u8>, String> {
        let mut file = oeffnen(path, "r")?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|e| format!("Datei nicht lesbar: {e}"))?;
        Ok(bytes)
    }

    pub fn write(path: &str, bytes: &[u8]) -> Result<(), String> {
        // Welche Betriebsart ein Anbieter annimmt, hängt vom Anbieter ab: Der
        // Download-Speicher lehnt „wt" ab, andere brauchen es, damit vom alten
        // Inhalt nichts stehenbleibt. Daher werden die Modi der Reihe nach probiert.
        let modi = ["wt", "rwt", "w", "rw"];

        let mut letzter = String::from("Datei nicht beschreibbar.");
        for modus in modi {
            match oeffnen(path, modus) {
                Err(e) => letzter = e,
                Ok(mut file) => {
                    file.write_all(bytes)
                        .map_err(|e| format!("Schreiben fehlgeschlagen: {e}"))?;

                    // Bei „w" statt „wt" bliebe alter, längerer Inhalt hinter
                    // dem neuen Ende stehen und die Datei wäre ungültig. Daher
                    // wird auf die neue Länge gekürzt.
                    if let Err(e) = file.set_len(bytes.len() as u64) {
                        eprintln!("[storage] {path} ließ sich nicht kürzen ({modus}): {e}");
                    }

                    file.sync_all()
                        .map_err(|e| format!("Synchronisieren fehlgeschlagen: {e}"))?;
                    return Ok(());
                }
            }
        }
        Err(letzter)
    }
}

/// Außerhalb von Android gibt es keine `content://`-Adressen; die Zweige
/// oben werden dort nie erreicht.
#[cfg(not(target_os = "android"))]
mod uri {
    pub fn remember(_path: &str) {}

    pub fn display_name(_path: &str) -> Option<String> {
        None
    }

    pub fn modified_ms(_path: &str) -> Option<i64> {
        None
    }

    pub fn read(path: &str) -> Result<Vec<u8>, String> {
        Err(format!("Adressen dieser Art gibt es hier nicht: {path}"))
    }

    pub fn write(path: &str, _bytes: &[u8]) -> Result<(), String> {
        Err(format!("Adressen dieser Art gibt es hier nicht: {path}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Der Download-Anbieter nennt den ganzen Pfad hinter `raw:`; angezeigt
    /// wird nur der Teil im Download-Ordner.
    #[test]
    fn download_adresse_zeigt_nur_den_namen() {
        let raw = "content://com.android.providers.downloads.documents/document/raw%3A%2Fstorage%2Femulated%2F0%2FDownload%2Fbeispiel.kdbx";
        assert_eq!(label(raw), "Downloads/beispiel.kdbx");
        assert_eq!(file_name(raw), "beispiel.kdbx");

        let tiefer = "content://com.android.providers.downloads.documents/document/raw%3A%2Fstorage%2Femulated%2F0%2FDownload%2FTresor%2Fa.kdbx";
        assert_eq!(label(tiefer), "Downloads/Tresor/a.kdbx");

        // Der Gerätespeicher bleibt unverändert.
        let primary = "content://com.android.externalstorage.documents/document/primary%3ADownload%2Ftest.kdbx";
        assert_eq!(label(primary), "Gerätespeicher/Download/test.kdbx");
    }

    /// Eine Adresse gilt immer als vorhanden, ein Pfad wird geprüft.
    #[test]
    fn adresse_gilt_als_vorhanden_pfad_wird_nachgesehen() {
        assert!(exists("content://org.nextcloud.documents/document/abc"));

        let ordner = std::env::temp_dir().join(format!("wkeepass-exists-{}", std::process::id()));
        std::fs::create_dir_all(&ordner).unwrap();
        let datei = ordner.join("da.kdbx");

        assert!(!exists(&datei.to_string_lossy()), "noch nicht angelegt");
        std::fs::write(&datei, b"x").unwrap();
        assert!(exists(&datei.to_string_lossy()));

        std::fs::remove_dir_all(&ordner).unwrap();
    }

    #[test]
    fn nur_content_adressen_sind_adressen() {
        assert!(is_uri("content://anbieter/dokument/1"));
        assert!(!is_uri("/home/du/passwoerter.kdbx"));
        assert!(!is_uri("C:\\Users\\du\\passwoerter.kdbx"));
    }
}
