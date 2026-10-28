//! Datenbank öffnen, auslesen und zurückschreiben.
//!
//! Das Entsperren liegt vollständig hier. Die Oberfläche fragt nur, welche
//! Wege es gibt (`unlock_methods`), und schickt dann einen davon los
//! (`vault_unlock`). Welcher Weg zum Master-Passwort führt, entscheidet der
//! Kern; die Oberfläche sieht das Passwort in keinem Fall.

use chrono::NaiveDateTime;
use keepass::db::EntryRef;
use keepass::{Database, DatabaseKey};
use zeroize::Zeroizing;

use crate::dto;
use crate::seal;
use crate::state::{all_folders, folder_path, is_recycled};
use crate::Vault;

/// Feldnamen, unter denen KeePass-Anwendungen das TOTP-Geheimnis ablegen.
const OTP_FIELDS: [&str; 2] = ["otp", "TOTP Seed"];

/// Woran KeePassXC einen Passkey-Eintrag erkennbar macht.
const PASSKEY_FIELD: &str = "KPEX_PASSKEY_USERNAME";

/* =========================================================
   Entsperren
   ========================================================= */

/// Welche Wege zum Entsperren gibt es auf diesem Gerät?
///
/// Asynchron, weil die Auskunft selbst warten kann: fprintd über D-Bus,
/// Windows Hello über WinRT. Auf dem Hauptfaden stünde so lange das Fenster.
#[tauri::command]
pub async fn unlock_methods(app: tauri::AppHandle, path: Option<String>) -> Result<dto::UnlockMethods, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let offer = seal::offer(&app, path.as_deref());
        let status = seal::status(&app);

        dto::UnlockMethods {
            password: true,
            pin: offer.pin,
            biometric: offer.biometric,
            biometric_available: crate::biometric::available(),
            keyring: offer.keyring,
            pin_set: status.pin_set,
            device: seal::device_offer(&app, path.as_deref()),
            device_available: crate::biometric::device_key_available(),
            device_label: crate::biometric::device_key_label().map(str::to_string),
        }
    })
    .await
    .map_err(|e| format!("Abgebrochen: {e}"))
}

/// Entsperrt und öffnet die Datenbank.
///
/// `method` ist `"password"`, `"pin"`, `"biometric"` oder `"device"`. Bei
/// `"password"` ist `secret` das Master-Passwort, bei `"pin"` die PIN; bei
/// den beiden anderen wird `secret` nicht gebraucht.
///
/// `remember` schaltet diese Datenbank gleich für PIN und/oder
/// Fingerabdruck frei — dafür muss die App-PIN bereits festgelegt sein.
///
/// # Warum das asynchron ist
///
/// Argon2 rechnet hier bewusst sekundenlang, und zwar bei richtigem wie bei
/// falschem Passwort gleichermaßen. Als synchrones Kommando liefe das auf
/// dem Hauptfaden und würde das Fenster so lange einfrieren — genau der
/// Effekt, den man dann für einen Absturz hält. Die teure Arbeit gehört
/// deshalb in einen eigenen Faden.
#[tauri::command]
pub async fn vault_unlock(
    app: tauri::AppHandle,
    state: tauri::State<'_, Vault>,
    path: String,
    method: String,
    secret: Option<String>,
    keyfile: Option<String>,
    #[allow(non_snake_case)] autoLockMinutes: Option<u64>,
    remember: Option<dto::Remember>,
) -> Result<dto::DatabaseInfo, String> {
    let auto_lock_minutes = autoLockMinutes.unwrap_or(0);

    let worker = app.clone();
    let target = path.clone();

    let Opened { db, raw, master, keyfile, format, read_only, offline, vorab } =
        tauri::async_runtime::spawn_blocking(move || open_blocking(&worker, &target, &method, secret, keyfile))
            .await
            .map_err(|e| format!("Entsperren abgebrochen: {e}"))??;

    // Wenn gewünscht, gleich eine PIN hinterlegen. Fehlschläge hier dürfen
    // das Öffnen nicht verhindern — die Datenbank ist ja auf.
    //
    // Das muss auf einen Arbeitsfaden, genau wie das Öffnen selbst: `remember`
    // prüft die PIN, und das heißt Argon2id — dieselbe absichtlich teure
    // Rechnung, mehrere Sekunden lang. Dazu kommt der Schlüsselbund über
    // D-Bus, der auf eine Antwort des Systems wartet. Beides direkt hier
    // auszuführen legt den Ausführer der Laufzeit lahm, über den auch die
    // Antwort an die Oberfläche zurückgeht — sie wartet dann ewig.
    let pin_note = match remember {
        // Der Geräteschlüssel braucht keine PIN, nur das Master-Passwort
        // und die Prüfung durch das Gerät.
        Some(r) if r.allow_device => {
            let worker = app.clone();
            let target = path.clone();
            let secret = master.to_string();

            tauri::async_runtime::spawn_blocking(move || {
                let device = seal::remember_device(&worker, &target, &secret).err();
                let pin = (r.allow_pin || r.allow_biometric)
                    .then(|| {
                        seal::remember(&worker, &target, &secret, &r.pin, r.allow_pin, r.allow_biometric)
                            .err()
                    })
                    .flatten();
                device.or(pin)
            })
            .await
            .map_err(|e| format!("Freigabe abgebrochen: {e}"))?
        }
        Some(r) if r.allow_pin || r.allow_biometric => {
            let worker = app.clone();
            let target = path.clone();
            let secret = master.to_string();

            tauri::async_runtime::spawn_blocking(move || {
                seal::remember(&worker, &target, &secret, &r.pin, r.allow_pin, r.allow_biometric)
                    .err()
            })
            .await
            .map_err(|e| format!("Freigabe abgebrochen: {e}"))?
        }
        _ => None,
    };

    // Auf Android ist der „Pfad" eine Adresse, in der oft nur eine Kennung
    // steht (Nextcloud: `…/document/5092c86d…`). Dann ist der Name aus der
    // Datenbank selbst die bessere Auskunft.
    let meta_name = db.meta.database_name.clone().filter(|n| !n.trim().is_empty());
    let name = match meta_name {
        Some(n) if crate::storage::is_uri(&path) => n,
        _ => crate::storage::file_name(&path),
    };

    // Für die Versionen: was in der Datei steht, bevor `db` weiterwandert.
    let abdruck = crate::versions::abdruck(&db);

    // Was länger als die Frist im Papierkorb liegt, ist jetzt weg. Erst nach
    // dem Abdruck: Die Version „geöffnet" soll zeigen, was in der Datei stand.
    let mut db = db;
    let aufgeraeumt = if read_only || offline.is_some() || vorab {
        0
    } else {
        crate::state::papierkorb_aufraeumen(&mut db, crate::state::PAPIERKORB_TAGE, keepass::db::Times::now())
    };

    let mut vault = state.lock().map_err(|_| "Kern blockiert.".to_string())?;
    vault.clear();
    vault.opened_config = Some(db.config.clone());
    vault.db = Some(db);
    vault.path = Some(path.clone().into());
    vault.master = Some(master);
    vault.keyfile = keyfile;
    vault.opened_hash = Some(digest(&raw));
    vault.seen_modified = crate::storage::modified_ms(&path);
    vault.read_only = read_only;
    // Vorab aus der Kopie: Bis der Stand vom Ort da ist, gilt die Datei als
    // nicht gelesen — `commit` liest dann vor dem Schreiben selbst.
    vault.offline = offline.is_some() || vorab;
    vault.auto_lock_minutes = auto_lock_minutes;
    vault.touch();

    drop(vault);

    // Entsperrt wird nicht mehr nur im Hauptfenster: Fragt ein Browser an,
    // während die Datei zu ist, geht die Anmeldemaske im kleinen Fenster auf.
    // Ohne diese Nachricht bliebe ein danebenstehendes Hauptfenster auf dem
    // Sperrbildschirm hängen, obwohl die Datenbank längst offen ist.
    // Netz unter dem Abgleich: So lag die Datei beim Öffnen da.
    // Im Hintergrund, aus demselben Grund wie die Offline-Kopie. Nach dem
    // Öffnen aus der Kopie nicht: Das wäre kein Stand der Datei.
    if !vorab {
        let (app, path) = (app.clone(), path.clone());
        std::thread::spawn(move || {
            let mut uhr = Uhr::neu();
            crate::versions::sichern(&app, &path, &raw, crate::versions::Grund::Geoeffnet, abdruck);
            uhr.schritt("Version gesichert (Hintergrund)");
        });
    }

    use tauri::Emitter;
    let _ = app.emit("vault-unlocked", &name);
    browser_announce(false);

    // Was Autofill während der Sperre speichern wollte, jetzt eintragen.
    #[cfg(target_os = "android")]
    {
        let mut uhr = Uhr::neu();
        crate::android_services::nach_entsperren(&app);
        uhr.schritt("Ausstehendes nachgetragen");
    }

    // Aus der Kopie geöffnet: den Stand vom Ort holen und einmischen.
    if vorab {
        let worker = app.clone();
        std::thread::spawn(move || nachladen(worker));
    }

    // Das Aufräumen im Papierkorb gleich zurückschreiben — im Hintergrund,
    // die Oberfläche hat ihre Liste schon ohne die alten Einträge.
    if aufgeraeumt > 0 {
        let worker = app.clone();
        tauri::async_runtime::spawn_blocking(move || {
            use tauri::Manager;
            if let Err(e) = commit(&worker, &worker.state::<Vault>()) {
                eprintln!("[papierkorb] {aufgeraeumt} alte Einträge entfernt, aber nicht gespeichert: {e}");
            }
        });
    }

    if let Some(note) = pin_note {
        return Err(format!("Geöffnet, aber die Freigabe wurde nicht gespeichert: {note}"));
    }

    let (cached_at, offline_reason) = offline.unzip();
    Ok(dto::DatabaseInfo { name, path, read_only, format, cached_at, offline_reason })
}

/// Zeitmessung beim Entsperren — eine Zeile je Schritt im Protokoll
/// (Android: logcat, Tag `RustStdoutStderr`). Am Handy dauerte das Öffnen
/// aus dem Ausfüll-Blatt einmal über 30 Sekunden; so sieht man, wo.
struct Uhr(std::time::Instant);

impl Uhr {
    fn neu() -> Self {
        Self(std::time::Instant::now())
    }
    fn schritt(&mut self, was: &str) {
        eprintln!("[entsperren] {was}: {} ms", self.0.elapsed().as_millis());
        self.0 = std::time::Instant::now();
    }
}

/// Ergebnis der teuren Arbeit, die außerhalb des Hauptfadens läuft.
struct Opened {
    db: Database,
    raw: Vec<u8>,
    master: Zeroizing<String>,
    /// Inhalt der Schlüsseldatei, falls eine dazugehört — gebraucht beim
    /// Zurückschreiben und beim Einlesen fremder Änderungen.
    keyfile: Option<Zeroizing<Vec<u8>>>,
    format: String,
    read_only: bool,
    /// Gesetzt, wenn statt der Datei die Offline-Kopie geöffnet wurde:
    /// (Zeitpunkt der Kopie, Grund).
    offline: Option<(String, String)>,
    /// Aus der Kopie geöffnet, ohne den Ort zu fragen — der Stand vom Ort
    /// kommt im Hintergrund nach (`nachladen`).
    vorab: bool,
}

/// Master-Passwort beschaffen, Datei lesen, Container aufschließen.
/// Alles hier drin darf dauern.
fn open_blocking(
    app: &tauri::AppHandle,
    path: &str,
    method: &str,
    secret: Option<String>,
    keyfile: Option<String>,
) -> Result<Opened, String> {
    let mut uhr = Uhr::neu();
    let master: Zeroizing<String> = match method {
        "password" => Zeroizing::new(secret.unwrap_or_default()),
        "pin" => seal::unseal_with_pin(app, path, &secret.unwrap_or_default())?,
        // Kein vorgeschaltetes `verify`: Das Gerät prüft beim Signieren selbst.
        "device" => seal::unseal_with_device(app, path)?,
        "biometric" => {
            // Erst der Nachweis, dass du es bist — dann erst kommt K ins
            // Spiel. Die Prüfung selbst macht die Plattform.
            crate::biometric::verify("Datenbank entsperren")?;
            seal::unseal_with_biometric(app, path)?
        }
        other => return Err(format!("Unbekannter Weg zum Entsperren: {other}")),
    };
    uhr.schritt("Schlüssel freigegeben");

    if master.is_empty() && keyfile.is_none() {
        return Err("Ohne Master-Passwort geht es nicht.".into());
    }

    // Einmal eingelesen und im Kern behalten: Die Datei muss beim Speichern
    // nicht mehr da sein, und die Datenbank bleibt mit ihr verschlüsselt.
    let keyfile = match &keyfile {
        Some(path) => Some(Zeroizing::new(
            std::fs::read(path).map_err(|e| format!("Schlüsseldatei nicht lesbar: {e}"))?,
        )),
        None => None,
    };
    let key = key_of(&master, keyfile.as_deref().map(|k| k.as_slice()))?;

    // Einmal komplett lesen: Daraus entsteht sowohl die Datenbank als auch
    // der Fingerabdruck, gegen den beim Speichern geprüft wird. Ist der Ort
    // nicht erreichbar, springt die Offline-Kopie ein.
    // Zuerst die eigene Kopie — der letzte Stand der App. Den Stand vom Ort
    // holt `nachladen` gleich danach und mischt ihn ein. Am Handy fragt
    // Nextcloud beim Öffnen erst seinen Server und lässt bis zu 30 Sekunden
    // warten, wenn der nicht antwortet; so lange stand vorher das
    // Ausfüll-Blatt. Gibt es keine Kopie oder passt sie nicht zum Schlüssel
    // (Passwort anderswo geändert), geht es den gewohnten Weg.
    {
        if let Some(kopie) = crate::offline::kopie(app, path) {
            if let Ok(db) = Database::parse(&kopie, key.clone()) {
                uhr.schritt("aus der Kopie entschlüsselt");
                let format = db.config.version.to_string();
                let read_only = !matches!(db.config.version, keepass::config::DatabaseVersion::KDB4(1));
                return Ok(Opened { db, raw: kopie, master, keyfile, format, read_only, offline: None, vorab: true });
            }
        }
    }

    let (raw, source) = crate::offline::read(app, path)?;
    uhr.schritt("Datei gelesen");

    let db = Database::parse(&raw, key).map_err(|e| match e {
        keepass::error::DatabaseOpenError::Key(_) => {
            "Falsches Passwort oder falsche Schlüsseldatei.".to_string()
        }
        other => format!("Datenbank konnte nicht geöffnet werden: {other}"),
    })?;
    uhr.schritt("entschlüsselt");

    // Zurückschreiben kann die Bibliothek nur KDBX 4.1.
    let format = db.config.version.to_string();
    let read_only = !matches!(db.config.version, keepass::config::DatabaseVersion::KDB4(1));
    spur(
        if matches!(source, crate::offline::Source::Original) { "geöffnet" } else { "geöffnet (Offline-Kopie)" },
        &raw,
        Some(&db),
    );

    // Erst nach dem Entschlüsseln kopieren: So landet nur eine Datei im
    // Zwischenspeicher, die sich mit diesem Schlüssel auch öffnen lässt.
    //
    // Im Hintergrund: Die Kopie ist ein Netz für später, und auf sie zu
    // warten hält am Handy das Ausfüll-Blatt auf.
    let offline = match source {
        crate::offline::Source::Original => {
            let (app, path, raw) = (app.clone(), path.to_string(), raw.clone());
            std::thread::spawn(move || crate::offline::store(&app, &path, &raw));
            None
        }
        crate::offline::Source::Cached { saved_at, reason } => Some((saved_at, reason)),
    };

    Ok(Opened { db, raw, master, keyfile, format, read_only, offline, vorab: false })
}

/// Legt eine neue, leere Datenbank an und öffnet sie gleich.
///
/// Genauso asynchron wie das Entsperren, und aus demselben Grund: Das
/// Verschlüsseln kostet dieselbe Rechenzeit.
#[tauri::command]
pub async fn vault_create(
    app: tauri::AppHandle,
    state: tauri::State<'_, Vault>,
    path: String,
    password: String,
    name: Option<String>,
    level: Option<String>,
    #[allow(non_snake_case)] autoLockMinutes: Option<u64>,
    remember: Option<dto::Remember>,
) -> Result<dto::DatabaseInfo, String> {
    if password.is_empty() {
        return Err("Eine neue Datenbank braucht ein Master-Passwort.".into());
    }
    // Auf Android legt der Speichern-Dialog die Datei selbst an; dort ist
    // „existiert schon" der Normalfall und kein Grund abzubrechen.
    if !crate::storage::is_uri(&path) && std::path::Path::new(&path).exists() {
        return Err("An dieser Stelle liegt schon eine Datei.".into());
    }

    let target = path.clone();
    let secret = password.clone();
    let title = name.clone().unwrap_or_default();

    tauri::async_runtime::spawn_blocking(move || {
        // `Database::new` liefert KDBX 4.1 — genau das, was sich auch
        // zurückschreiben lässt.
        let mut db = Database::new();

        // Ohne Stufe bliebe die Voreinstellung der Bibliothek: Argon2d mit
        // 1 MiB — viel zu wenig.
        stufe_setzen(&mut db, level.as_deref().unwrap_or("standard"))?;

        // Der Name steht in der Datei selbst. Das ist unter Android die
        // einzige verlässliche Bezeichnung: Aus der Adresse des Systems
        // lässt sich keine herausholen.
        if !title.trim().is_empty() {
            db.meta.database_name = Some(title.trim().to_string());
            db.meta.database_name_changed = Some(chrono::Local::now().naive_local());
        }

        let mut bytes: Vec<u8> = Vec::new();
        db.save(&mut bytes, DatabaseKey::new().with_password(&secret))
            .map_err(|e| format!("Anlegen fehlgeschlagen: {e}"))?;

        crate::storage::write(&target, &bytes)
    })
    .await
    .map_err(|e| format!("Anlegen abgebrochen: {e}"))??;

    vault_unlock(app, state, path, "password".into(), Some(password), None, autoLockMinutes, remember).await
}

/// SHA-256 über den Dateiinhalt — nur zum Erkennen fremder Änderungen,
/// nichts Geheimes.
fn digest(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).into()
}

/// Eine Zeile ins Browser-Protokoll (`api::protokolliere`), wenn es an ist:
/// Kurzform des Fingerabdrucks und wie viele Browser verknüpft sind — um zu
/// sehen, ob die Datei zwischen zwei Starts ersetzt wurde.
fn spur(was: &str, bytes: &[u8], db: Option<&Database>) {
    #[cfg(desktop)]
    {
        let abdruck: String = digest(bytes)[..4].iter().map(|b| format!("{b:02x}")).collect();
        let verknuepft = db.map_or(String::new(), |db| {
            let n = db.meta.custom_data.keys().filter(|k| k.starts_with("KPXC_BROWSER_")).count();
            format!(", Verknüpfungen {n}")
        });
        crate::keepass_extension::api::protokolliere(&format!("Datei {was}: Abdruck {abdruck}{verknuepft}"));
    }
    #[cfg(not(desktop))]
    let _ = (was, bytes, db);
}

/// Wie die Datei beim Beenden aussieht — fürs Protokoll.
pub fn spur_beim_beenden(app: &tauri::AppHandle) {
    use tauri::Manager;
    let Some(ziel) = app.state::<Vault>().lock().ok().and_then(|v| v.path.clone()) else { return };
    if let Ok(bytes) = crate::storage::read(&ziel.to_string_lossy()) {
        spur("beim Beenden", &bytes, None);
    }
}

/// Legt die PIN des Programms fest. Sie gilt für alle Datenbanken.
///
/// Asynchron, weil Argon2 auch hier sekundenlang rechnet.
#[tauri::command]
pub async fn app_pin_create(app: tauri::AppHandle, pin: String) -> Result<bool, String> {
    tauri::async_runtime::spawn_blocking(move || seal::create_pin(&app, &pin))
        .await
        .map_err(|e| format!("Abgebrochen: {e}"))??;
    Ok(true)
}

/// Ändert die PIN — nur gegen die alte, und wickelt dabei alle Freigaben
/// um. Eine Wiederherstellung gibt es nicht.
#[tauri::command]
pub async fn app_pin_change(app: tauri::AppHandle, old: String, new: String) -> Result<bool, String> {
    tauri::async_runtime::spawn_blocking(move || seal::change_pin(&app, &old, &new))
        .await
        .map_err(|e| format!("Abgebrochen: {e}"))??;
    Ok(true)
}

/// Verwirft PIN, Schlüssel und sämtliche Freigaben.
#[tauri::command]
pub fn app_pin_clear(app: tauri::AppHandle) -> Result<bool, String> {
    seal::clear(&app)?;
    Ok(true)
}

/// Schaltet die **offene** Datenbank für PIN und/oder Fingerabdruck frei.
///
/// Das Master-Passwort kommt aus dem Kern; die PIN muss eingegeben werden,
/// weil ohne sie kein App-Schlüssel entsteht.
#[tauri::command]
pub async fn vault_remember(
    app: tauri::AppHandle,
    state: tauri::State<'_, Vault>,
    pin: String,
    #[allow(non_snake_case)] allowPin: bool,
    #[allow(non_snake_case)] allowBiometric: bool,
) -> Result<bool, String> {
    let (path, master) = {
        let vault = state.lock().map_err(|_| "Kern blockiert.".to_string())?;
        let path = vault
            .path
            .clone()
            .ok_or("Keine Datenbank geöffnet.")?
            .to_string_lossy()
            .to_string();
        let master = vault.master.as_ref().ok_or("Keine Datenbank geöffnet.")?.to_string();
        (path, master)
    };

    tauri::async_runtime::spawn_blocking(move || {
        seal::remember(&app, &path, &master, &pin, allowPin, allowBiometric)
    })
    .await
    .map_err(|e| format!("Abgebrochen: {e}"))??;
    Ok(true)
}

/// Schaltet die **offene** Datenbank gerätegebunden frei (Windows Hello) —
/// oder nimmt das zurück. Ohne PIN: Der Schutz kommt aus dem TPM.
#[tauri::command]
pub async fn vault_remember_device(
    app: tauri::AppHandle,
    state: tauri::State<'_, Vault>,
    enable: bool,
) -> Result<bool, String> {
    let (path, master) = {
        let vault = state.lock().map_err(|_| "Kern blockiert.".to_string())?;
        let path = vault
            .path
            .clone()
            .ok_or("Keine Datenbank geöffnet.")?
            .to_string_lossy()
            .to_string();
        let master = vault.master.as_ref().ok_or("Keine Datenbank geöffnet.")?.to_string();
        (path, master)
    };

    tauri::async_runtime::spawn_blocking(move || {
        if enable {
            seal::remember_device(&app, &path, &master)
        } else {
            seal::forget_device(&app, &path)
        }
    })
    .await
    .map_err(|e| format!("Abgebrochen: {e}"))??;
    Ok(true)
}

/// Nimmt die Freigabe einer Datenbank zurück. Die PIN bleibt bestehen.
#[tauri::command]
pub fn vault_forget(app: tauri::AppHandle, path: String) -> Result<bool, String> {
    seal::forget(&app, &path)?;
    Ok(true)
}

/// „Ich bin es" bestätigen, ohne die Datenbank anzufassen — für das
/// Anzeigen eines Passworts oder eine Anfrage aus dem Browser.
///
/// Drei Wege, und welche davon zur Auswahl stehen, sagt `unlock_methods`:
///
///   `pin`        die App-PIN. Sie gilt hier **immer**, wenn eine festgelegt
///                ist — auch wenn diese Datenbank nicht per PIN geöffnet
///                werden darf. Zum Entsperren ist sie ein Schlüssel, hier
///                nur ein Nachweis, und das sind zwei verschiedene Fragen.
///   `master`     das Master-Passwort der offenen Datenbank.
///   `biometric`  Fingerabdruck oder Gesicht.
#[tauri::command]
pub async fn confirm_presence(
    app: tauri::AppHandle,
    state: tauri::State<'_, Vault>,
    reason: String,
    method: Option<String>,
    secret: Option<String>,
) -> Result<bool, String> {
    match method.as_deref() {
        // Das Master-Passwort der offenen Datenbank. Es liegt ohnehin im
        // Kern; verglichen wird dort, es verlässt ihn nicht.
        Some("master") => {
            let given = secret.ok_or("Kein Passwort angegeben.")?;

            let vault = state.lock().map_err(|_| "Kern blockiert.".to_string())?;
            let master = vault.master.as_ref().ok_or("Keine Datenbank geöffnet.")?;

            // Zeichenweiser Vergleich in fester Zeit wäre hier übertrieben:
            // Wer den Kern messen kann, hat ihn ohnehin.
            if given.as_str() == master.as_str() {
                Ok(true)
            } else {
                Err("Master-Passwort stimmt nicht.".into())
            }
        }

        Some("biometric") => {
            // Auf einen Arbeitsfaden: Die Prüfung wartet auf den Finger des
            // Nutzers — unter Linux über D-Bus bei fprintd, anderswo beim
            // System. Auf dem Ausführer der Laufzeit stünde währenddessen
            // die ganze Oberfläche.
            tauri::async_runtime::spawn_blocking(move || crate::biometric::verify(&reason))
                .await
                .map_err(|e| format!("Abgebrochen: {e}"))?
                .map(|()| true)
        }

        // Voreinstellung ist die PIN — auch ohne ausdrückliche Angabe, damit
        // ältere Aufrufe weiter gelten.
        _ => {
            let pin = secret.ok_or("Keine PIN angegeben.")?;
            tauri::async_runtime::spawn_blocking(move || seal::confirm_pin(&app, &pin))
                .await
                .map_err(|e| format!("Abgebrochen: {e}"))??;
            Ok(true)
        }
    }
}

/* =========================================================
   Versionen
   ---------------------------------------------------------
   Die Stände selbst liegen in `versions.rs`; hier ist nur die Tür für die
   Oberfläche. Entschlüsselt wird mit dem Schlüssel der offenen Datenbank —
   ohne offene Datenbank gibt es keinen Blick zurück.
   ========================================================= */

/// Die aufgehobenen Stände der offenen Datenbank, der jüngste zuerst.
#[tauri::command]
pub fn vault_versions(
    app: tauri::AppHandle,
    state: tauri::State<'_, Vault>,
) -> Result<Vec<dto::Version>, String> {
    let vault = state.lock().map_err(|_| "Kern blockiert.".to_string())?;
    let pfad = vault.path.as_ref().ok_or("Keine Datenbank geöffnet.")?.to_string_lossy().to_string();
    let offen = vault.opened_hash;
    Ok(crate::versions::liste(&app, &pfad, |bytes| Some(digest(bytes)) == offen))
}

/// Was sich seit diesem Stand geändert hat.
#[tauri::command]
pub async fn vault_version_changes(
    app: tauri::AppHandle,
    state: tauri::State<'_, Vault>,
    id: String,
) -> Result<Vec<dto::VersionChange>, String> {
    let (pfad, master, keyfile) = {
        let vault = state.lock().map_err(|_| "Kern blockiert.".to_string())?;
        let master = vault.master.as_ref().ok_or("Keine Datenbank geöffnet.")?.clone();
        let pfad = vault.path.as_ref().ok_or("Keine Datenbank geöffnet.")?.to_string_lossy().to_string();
        (pfad, master, vault.keyfile.clone())
    };

    // Entschlüsseln dauert — nicht auf dem Ausführer der Laufzeit.
    let worker = app.clone();
    let alt = tauri::async_runtime::spawn_blocking(move || {
        let bytes = crate::versions::lesen(&worker, &pfad, &id)?;
        parse_with(&master, keyfile.as_deref().map(|k| k.as_slice()), &bytes)
    })
    .await
    .map_err(|e| format!("Abgebrochen: {e}"))??;

    let vault = state.lock().map_err(|_| "Kern blockiert.".to_string())?;
    Ok(crate::versions::vergleich(&alt, vault.database()?))
}

/// Was mit diesem Stand dazukam: der Vergleich mit dem Stand davor.
///
/// So liest sich die Liste wie ein Verlauf — jeder Stand sagt, was er
/// geändert hat, nicht alles, was seitdem geschah. `vorher` ist der Stand,
/// aus dem „Zurücknehmen" holt; fehlt er, ist dies der älteste.
#[tauri::command]
pub async fn vault_version_step(
    app: tauri::AppHandle,
    state: tauri::State<'_, Vault>,
    id: String,
) -> Result<dto::VersionStep, String> {
    let (pfad, master, keyfile) = {
        let vault = state.lock().map_err(|_| "Kern blockiert.".to_string())?;
        let master = vault.master.as_ref().ok_or("Keine Datenbank geöffnet.")?.clone();
        let pfad = vault.path.as_ref().ok_or("Keine Datenbank geöffnet.")?.to_string_lossy().to_string();
        (pfad, master, vault.keyfile.clone())
    };

    let worker = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let oeffne = |stand: &str| {
            let bytes = crate::versions::lesen(&worker, &pfad, stand)?;
            parse_with(&master, keyfile.as_deref().map(|k| k.as_slice()), &bytes)
        };
        let Some(vorher) = crate::versions::vorgaenger(&worker, &pfad, &id) else {
            return Ok(dto::VersionStep { previous: None, changes: Vec::new() });
        };

        // Ein zusammengeführter Stand: Davor liegt der Stand der Datei
        // („Vom anderen Gerät“), davor der letzte eigene. Gezeigt wird alles
        // seit dem eigenen — je Änderung mit Herkunft: aus der Datei
        // (`extern`), aus der App (`hier`) oder beides.
        if crate::versions::grund_von(&id) == "zusammengefuehrt" && crate::versions::grund_von(&vorher) == "fremd" {
            if let Some(basis_id) = crate::versions::vorgaenger(&worker, &pfad, &vorher) {
                let basis = oeffne(&basis_id)?;
                let datei = oeffne(&vorher)?;
                let jetzt = oeffne(&id)?;
                let extern_: std::collections::HashSet<String> =
                    crate::versions::vergleich(&basis, &datei).into_iter().map(|c| c.id).collect();
                let hier: std::collections::HashSet<String> =
                    crate::versions::vergleich(&datei, &jetzt).into_iter().map(|c| c.id).collect();
                let changes = crate::versions::vergleich(&basis, &jetzt)
                    .into_iter()
                    .map(|mut c| {
                        c.origin = Some(
                            match (extern_.contains(&c.id), hier.contains(&c.id)) {
                                (true, true) => "beide",
                                (true, false) => "extern",
                                _ => "hier",
                            }
                            .to_string(),
                        );
                        c
                    })
                    .collect();
                return Ok(dto::VersionStep { previous: Some(basis_id), changes });
            }
        }

        let changes = crate::versions::vergleich(&oeffne(&vorher)?, &oeffne(&id)?);
        Ok(dto::VersionStep { previous: Some(vorher), changes })
    })
    .await
    .map_err(|e| format!("Abgebrochen: {e}"))?
}

/// Holt einen Stand zurück — alles oder einzelne Einträge.
///
/// Geschrieben wird dabei noch nichts: Der Aufrufer speichert danach wie
/// nach jeder anderen Änderung. So sieht man das Ergebnis erst und kann es
/// im Zweifel liegen lassen.
#[tauri::command]
pub async fn vault_version_restore(
    app: tauri::AppHandle,
    state: tauri::State<'_, Vault>,
    id: String,
    entries: Option<Vec<String>>,
) -> Result<usize, String> {
    let (pfad, master, keyfile) = {
        let vault = state.lock().map_err(|_| "Kern blockiert.".to_string())?;
        let master = vault.master.as_ref().ok_or("Keine Datenbank geöffnet.")?.clone();
        let pfad = vault.path.as_ref().ok_or("Keine Datenbank geöffnet.")?.to_string_lossy().to_string();
        (pfad, master, vault.keyfile.clone())
    };

    let worker = app.clone();
    let alt = tauri::async_runtime::spawn_blocking(move || {
        let bytes = crate::versions::lesen(&worker, &pfad, &id)?;
        parse_with(&master, keyfile.as_deref().map(|k| k.as_slice()), &bytes)
    })
    .await
    .map_err(|e| format!("Abgebrochen: {e}"))??;

    let mut vault = state.lock().map_err(|_| "Kern blockiert.".to_string())?;
    vault.touch();
    let jetzt = vault.database_mut()?;

    match entries {
        Some(liste) => {
            for uuid in &liste {
                crate::versions::eintrag_zurueck(jetzt, &alt, uuid)?;
            }
            Ok(liste.len())
        }
        None => crate::versions::alles_zurueck(jetzt, &alt),
    }
}

/* =========================================================
   Lesen
   ========================================================= */

/// Alles, was ein Eintrag mitbringt, bevor die Token vergeben sind.
struct RawEntry {
    entry: dto::Entry,
    password: Option<String>,
    totp: Option<String>,
}

#[tauri::command]
pub fn vault_list_entries(state: tauri::State<'_, Vault>) -> Result<Vec<dto::Entry>, String> {
    let mut vault = state.lock().map_err(|_| "Kern blockiert.".to_string())?;

    // Erst lesen (leiht die Datenbank aus), dann Token vergeben (leiht den
    // Zustand veränderlich aus). Beides zugleich ginge nicht.
    let mut raws: Vec<RawEntry> = {
        let db = vault.database()?;
        db.iter_all_entries().map(|e| read_entry(db, &e)).collect()
    };

    let mut out = Vec::with_capacity(raws.len());
    for raw in raws.drain(..) {
        let RawEntry { mut entry, password, totp } = raw;
        let uuid = entry.id.clone().unwrap_or_default();

        if let Some(value) = password {
            let token = vault.token_for(&uuid, "Password");
            vault.secrets.insert(token.clone(), Zeroizing::new(value));
            entry.has_password = true;
            entry.password_token = Some(token);
        }

        if let Some(value) = totp {
            let token = vault.token_for(&uuid, "otp");
            vault.secrets.insert(token.clone(), Zeroizing::new(value));
            entry.has_totp = true;
            entry.totp_token = Some(token);
        }

        out.push(entry);
    }

    Ok(out)
}

#[tauri::command]
pub fn vault_folders(state: tauri::State<'_, Vault>) -> Result<Vec<String>, String> {
    let vault = state.lock().map_err(|_| "Kern blockiert.".to_string())?;
    Ok(all_folders(vault.database()?))
}

/// Übersetzt einen Eintrag in die Form, die die Oberfläche erwartet.
///
/// Nimmt `EntryRef` und nicht `Entry`, weil Anhänge und Elterngruppe an der
/// Datenbank hängen, nicht am Eintrag selbst.
fn read_entry(db: &Database, entry: &EntryRef<'_>) -> RawEntry {
    let uuid = entry.id().uuid().to_string();

    let otp_raw = OTP_FIELDS.iter().find_map(|f| entry.get(f)).filter(|v| !v.is_empty());
    let totp_config = otp_raw.and_then(parse_totp_config).unwrap_or_default();

    let attachments = entry
        .attachments_named()
        .map(|(name, att)| dto::AttachmentLink {
            name: name.to_string(),
            reference: att.id().id().to_string(),
        })
        .collect();

    let expires = match (entry.times.expires, entry.times.expiry) {
        (Some(true), Some(at)) => Some(at.format("%Y-%m-%d").to_string()),
        _ => None,
    };

    RawEntry {
        entry: dto::Entry {
            id: Some(uuid),
            folder: folder_path(db, entry.parent().id()),
            name: entry.get_title().unwrap_or_default().to_string(),
            username: entry.get_username().unwrap_or_default().to_string(),
            url: entry.get_url().unwrap_or_default().to_string(),
            notes: entry.get(keepass::db::fields::NOTES).unwrap_or_default().to_string(),
            tags: entry.tags.clone(),
            modified: iso(entry.times.last_modification),
            accessed: iso(entry.times.last_access.or(entry.times.last_modification)),

            // Die Token folgen erst, wenn der Zustand veränderlich vorliegt.
            has_password: false,
            password_token: None,
            has_totp: false,
            totp_token: None,
            totp_config,

            passkey: entry.get(PASSKEY_FIELD).is_some() || entry.get("Passkey") == Some("True"),
            passkey_site: entry.get("KPEX_PASSKEY_RELYING_PARTY").map(str::to_string),
            passkey_user: entry.get(PASSKEY_FIELD).map(str::to_string),
            icon: crate::favicon::data_url(&entry),
            expires,
            attachments,
            recycled: is_recycled(db, entry.parent().id()),
            recycled_since: crate::state::im_papierkorb_seit(db, entry.parent().id(), entry.times.location_changed)
                .map(|t| iso(Some(t))),
        },
        password: entry.get_password().filter(|v| !v.is_empty()).map(str::to_string),
        totp: otp_raw.map(str::to_string),
    }
}

/// Liest Ziffern, Zeitfenster und Verfahren aus einer `otpauth://`-Adresse.
fn parse_totp_config(raw: &str) -> Option<dto::TotpConfig> {
    let totp: keepass::db::TOTP = raw.parse().ok()?;
    Some(dto::TotpConfig {
        digits: totp.digits,
        period: totp.period,
        algorithm: match totp.algorithm {
            keepass::db::TOTPAlgorithm::Sha256 => "SHA256".into(),
            keepass::db::TOTPAlgorithm::Sha512 => "SHA512".into(),
            _ => "SHA1".into(),
        },
        at: None,
    })
}

fn iso(time: Option<NaiveDateTime>) -> String {
    time.unwrap_or_else(keepass::db::Times::now).format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/* =========================================================
   Name und Verschlüsselung
   ---------------------------------------------------------
   Der Schlüssel entsteht nicht direkt aus dem Master-Passwort: Eine
   Ableitungsfunktion rechnet absichtlich lange daran. Je länger, desto
   teurer wird jeder Rateversuch — und desto länger dauert auch das eigene
   Öffnen. Deshalb fünf Stufen statt einer Zahl.
   ========================================================= */

/// Die Stufen: (Durchgänge, Speicher in MiB, Fäden). Benannt sind in der
/// Oberfläche nur „Schnell“, „Standard“ und „Stark“.
///
/// „Standard“ belegt nur 16 MiB: Mehr gibt iOS dem Ausfüllen über die
/// Tastatur nicht (KeePassium meldet sich dann mit einem Hinweis), und die
/// Datei soll auf jedem Gerät aufgehen. Die Durchgänge gleichen das aus —
/// Standard rechnet so lange wie früher 10 × 64 MiB. Darüber geht es mit
/// dem Speicher hoch (64, 128, 256 MiB); das sind genau die früheren
/// Stufen Standard, Erhöht und Stark, Dateien mit diesen Werten werden also
/// weiter erkannt.
const STUFEN: [(&str, u64, u64, u32); 6] = [
    ("schnell", 10, 16, 2),
    ("zuegig", 20, 16, 2),
    ("standard", 40, 16, 4),
    ("erhoeht", 10, 64, 4),
    ("hoch", 14, 128, 4),
    ("stark", 20, 256, 4),
];

/// Setzt die Schlüsselableitung einer Stufe.
fn stufe_setzen(db: &mut Database, level: &str) -> Result<(), String> {
    use keepass::config::KdfConfig;

    let (_, iterations, memory_mib, parallelism) = STUFEN
        .iter()
        .find(|(name, ..)| *name == level)
        .ok_or_else(|| format!("Unbekannte Stufe: {level}"))?;

    // Argon2id statt Argon2d: Es hält zusätzlich Angriffen über
    // Seitenkanäle stand und ist das, was KeePassXC heute vorgibt.
    db.config.kdf_config = KdfConfig::Argon2id {
        iterations: *iterations,
        memory: memory_mib * 1024 * 1024,
        parallelism: *parallelism,
        // Die Fassung, die auch die Bibliothek voreinstellt (0x13).
        version: Default::default(),
    };
    Ok(())
}

fn stufe_von(iterations: u64, memory_mib: u64, parallelism: u32) -> String {
    STUFEN
        .iter()
        .find(|(_, i, m, p)| *i == iterations && *m == memory_mib && *p == parallelism)
        .map(|(name, ..)| (*name).to_string())
        .unwrap_or_else(|| "eigen".to_string())
}

#[tauri::command]
pub fn vault_security(state: tauri::State<'_, Vault>) -> Result<dto::Security, String> {
    use keepass::config::{KdfConfig, OuterCipherConfig};

    let vault = state.lock().map_err(|_| "Kern blockiert.".to_string())?;
    let db = vault.database()?;

    let (kdf, iterations, memory, parallelism) = match db.config.kdf_config {
        KdfConfig::Aes { rounds } => ("AES-KDF".to_string(), rounds, 0, 0),
        KdfConfig::Argon2 { iterations, memory, parallelism, .. } => {
            ("Argon2d".to_string(), iterations, memory, parallelism)
        }
        KdfConfig::Argon2id { iterations, memory, parallelism, .. } => {
            ("Argon2id".to_string(), iterations, memory, parallelism)
        }
        _ => ("unbekannt".to_string(), 0, 0, 0),
    };

    let cipher = match db.config.outer_cipher_config {
        OuterCipherConfig::AES256 => "AES-256",
        OuterCipherConfig::Twofish => "Twofish",
        OuterCipherConfig::ChaCha20 => "ChaCha20",
        _ => "unbekannt",
    };

    // KDBX führt den Speicher in Byte, gedacht wird er in MiB.
    let memory_mib = memory / (1024 * 1024);

    Ok(dto::Security {
        name: db.meta.database_name.clone().unwrap_or_default(),
        format: db.config.version.to_string(),
        read_only: vault.read_only,
        level: stufe_von(iterations, memory_mib, parallelism),
        kdf,
        iterations,
        memory_mib,
        parallelism,
        cipher: cipher.to_string(),
    })
}

/// Setzt Name und/oder Stufe. Wirksam wird beides mit dem nächsten Speichern.
#[tauri::command]
pub fn vault_set_security(
    state: tauri::State<'_, Vault>,
    name: Option<String>,
    level: Option<String>,
) -> Result<bool, String> {
    let mut vault = state.lock().map_err(|_| "Kern blockiert.".to_string())?;
    vault.touch();
    if vault.read_only {
        return Err("Diese Datei lässt sich nicht zurückschreiben.".into());
    }

    let db = vault.database_mut()?;

    if let Some(name) = name {
        let name = name.trim().to_string();
        db.meta.database_name_changed = Some(chrono::Local::now().naive_local());
        db.meta.database_name = (!name.is_empty()).then_some(name);
    }

    if let Some(level) = level {
        stufe_setzen(db, &level)?;
    }

    Ok(true)
}

/* =========================================================
   Schreiben und Sperren
   ========================================================= */

#[tauri::command]
pub fn vault_commit(app: tauri::AppHandle, state: tauri::State<'_, Vault>) -> Result<bool, String> {
    commit(&app, &state)
}

/// Schreibt die Datenbank zurück.
///
/// Steht als eigene Funktion da, weil nicht nur die Oberfläche schreibt: Die
/// Browser-Anbindung legt Verknüpfungen und Einträge an, und die wären beim
/// nächsten Start weg, wenn sie nur im Arbeitsspeicher stünden.
///
/// Hat seit dem Öffnen ein anderes Gerät geschrieben — die Datei liegt in
/// Nextcloud und wird auch von KeePassXC angefasst —, wird dessen Stand erst
/// eingelesen und mit dem eigenen zusammengeführt (`merge`). Geschrieben
/// wird dann beides; verloren geht keine Seite.
pub fn commit(app: &tauri::AppHandle, state: &Vault) -> Result<bool, String> {
    // Erst in der App: verschlüsselt in die eigene Kopie. Das ist der Stand,
    // mit dem die App arbeitet — er bleibt, auch wenn die Cloud gerade nicht
    // antwortet oder die App beendet wird.
    {
        let mut vault = state.lock().map_err(|_| "Kern blockiert.".to_string())?;
        vault.touch();
        if vault.read_only {
            return Err(
                "Diese Datei lässt sich nicht zurückschreiben — gespeichert wird nur KDBX 4.1. \
                 Wandle sie in KeePassXC um (Datenbank → Datenbankeinstellungen → Format)."
                    .into(),
            );
        }
        let ziel = vault.path.clone().ok_or("Keine Datenbank geöffnet.")?.to_string_lossy().to_string();
        let bytes = verschluesseln(&vault)?;
        crate::offline::store(app, &ziel, &bytes);
        vault.ausstehend = true;
    }

    // Dann der Ort: Datei holen, zusammenführen, schreiben — im Hintergrund.
    im_hintergrund_abgleichen(app);
    Ok(true)
}

/// Verschlüsselt den Stand im Kern, wie er in eine Datei käme.
fn verschluesseln(vault: &crate::state::VaultState) -> Result<Vec<u8>, String> {
    let master = vault.master.as_ref().ok_or("Kein Master-Passwort im Kern.")?;
    let key = key_of(master, vault.keyfile.as_deref().map(|k| k.as_slice()))?;
    let mut bytes: Vec<u8> = Vec::new();
    vault
        .database()?
        .save(&mut bytes, key)
        .map_err(|e| format!("Verschlüsseln fehlgeschlagen: {e}"))?;
    Ok(bytes)
}

/// Immer nur ein Abgleich mit dem Ort zugleich — sonst schrieben zwei
/// Fäden dieselbe Datei.
fn abgleich_riegel() -> &'static std::sync::Mutex<()> {
    static RIEGEL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    &RIEGEL
}

/// Startet [`abgleichen`] auf einem eigenen Faden. Klappt es nicht, bleibt
/// der Stand in der App und wird beim nächsten Abgleich nachgeholt; die
/// Oberfläche erfährt es (`vault-sync-failed`).
fn im_hintergrund_abgleichen(app: &tauri::AppHandle) {
    let app = app.clone();
    std::thread::spawn(move || {
        use tauri::{Emitter, Manager};
        let Ok(_riegel) = abgleich_riegel().lock() else { return };
        // Ein früherer Faden hat es schon erledigt.
        if !app.state::<Vault>().lock().is_ok_and(|v| v.ausstehend && v.db.is_some()) {
            return;
        }
        match abgleichen(&app, &app.state::<Vault>()) {
            Ok(_) => {}
            Err(err) => {
                eprintln!("[abgleich] nicht geschrieben, bleibt in der App: {err}");
                let _ = app.emit("vault-sync-failed", err);
            }
        }
    });
}

/// Bringt den Stand der App in die Datei am Ort: Datei frisch holen (es
/// könnte sich inzwischen etwas getan haben), mit dem Stand in der App
/// zusammenführen, schreiben — Datei und eigene Kopie.
pub fn abgleichen(app: &tauri::AppHandle, state: &Vault) -> Result<bool, String> {
    // Die Datei erst lesen, dann den Kern festhalten: Am Handy fragt
    // Nextcloud beim Öffnen seinen Server, und antwortet der nicht, dauert
    // das bis zu 30 Sekunden. So lange war vorher der ganze Kern blockiert —
    // auch das nächste Ausfüllen.
    // Kein `touch`: Das läuft im Hintergrund (auch der regelmäßige Abgleich)
    // und ist keine Nutzung — sonst sperrte sich die Datenbank nie.
    let (ziel, offline) = {
        let vault = state.lock().map_err(|_| "Kern blockiert.".to_string())?;

        if vault.read_only {
            return Err(
                "Diese Datei lässt sich nicht zurückschreiben — gespeichert wird nur KDBX 4.1. \
                 Wandle sie in KeePassXC um (Datenbank → Datenbankeinstellungen → Format)."
                    .into(),
            );
        }
        let ziel = vault.path.clone().ok_or("Keine Datenbank geöffnet.")?.to_string_lossy().to_string();
        (ziel, vault.offline)
    };

    // Geöffnet ist nur die Offline-Kopie. Zurückschreiben geht erst, wenn
    // die Datei wieder lesbar ist — sonst entstünde am Ort womöglich eine
    // neue Datei neben einer, die gerade nur nicht erreichbar ist.
    let current = crate::storage::read(&ziel);
    if offline && current.is_err() {
        return Err(
            "Der Speicherort ist gerade nicht erreichbar — geöffnet ist die Offline-Kopie. \
             Gespeichert werden kann erst, wenn die Datei wieder da ist."
                .into(),
        );
    }

    // Die Datei ist da, lässt sich aber gerade nicht lesen: Dann wird nicht
    // geschrieben. Vorher ging es hier ohne Abgleich weiter — und was ein
    // anderes Gerät inzwischen abgelegt hatte, war damit überschrieben,
    // ohne dass es je gelesen worden wäre. Nur wenn es die Datei wirklich
    // nicht mehr gibt, wird sie neu angelegt.
    if let Err(grund) = &current {
        if crate::storage::exists(&ziel) {
            return Err(format!(
                "Die Datei lässt sich gerade nicht lesen ({grund}). Es wurde nichts geschrieben, \
                 damit nichts verloren geht, was ein anderes Gerät dort abgelegt hat. \
                 Deine Änderungen bleiben in der App — gleich noch einmal speichern."
            ));
        }
    }

    let mut vault = state.lock().map_err(|_| "Kern blockiert.".to_string())?;
    // Inzwischen gesperrt oder eine andere Datei geöffnet: nichts zu tun.
    if vault.path.as_deref().map(|p| p.to_string_lossy().to_string()).as_deref() != Some(ziel.as_str()) || vault.db.is_none() {
        return Err("Keine Datenbank geöffnet.".into());
    }

    let mut merged = false;
    let mut konflikte = 0;
    if let Ok(current) = current {
        if vault.opened_hash != Some(digest(&current)) {
            let theirs = parse_foreign(&vault, &current)?;
            spur("seit dem Öffnen fremd geändert", &current, Some(&theirs));
            let basis = basis_lesen(app, &ziel, &vault);
            crate::versions::sichern(app, &ziel, &current, crate::versions::Grund::Fremd, crate::versions::abdruck(&theirs));
            let gesehen = vault.opened_config.clone();
            einstellungen_uebernehmen(vault.database_mut()?, &theirs, gesehen.as_ref());
            let vorher = vault.database()?.clone();
            merged = merge(vault.database_mut()?, &theirs)?.0;
            konflikte = konflikte_merken(&mut vault, basis.as_ref(), vorher, theirs)?;
        }
    }

    let grund = if merged { crate::versions::Grund::Zusammengefuehrt } else { crate::versions::Grund::Gespeichert };
    write_back_als(app, &mut vault, &ziel, grund)?;
    drop(vault);

    use tauri::Emitter;
    if merged {
        let _ = app.emit("vault-merged", ());
    }
    if konflikte > 0 {
        let _ = app.emit("vault-conflicts", konflikte);
    }
    Ok(true)
}

/// Der letzte gemeinsame Stand mit der Datei: der jüngste aufgehobene —
/// zu lesen, bevor der fremde Stand selbst abgelegt wird.
fn basis_lesen(app: &tauri::AppHandle, ziel: &str, vault: &crate::state::VaultState) -> Option<Database> {
    let bytes = crate::versions::juengster(app, ziel)?;
    parse_foreign(vault, &bytes).ok()
}

/// Sucht nach dem Zusammenführen die Einträge, die beide Seiten verschieden
/// geändert haben, und hält sie zur Entscheidung bereit. Zurück: wie viele
/// jetzt offen sind.
fn konflikte_merken(
    vault: &mut crate::state::VaultState,
    basis: Option<&Database>,
    hier: Database,
    datei: Database,
) -> Result<usize, String> {
    let Some(basis) = basis else { return Ok(vault.konflikte.len()) };
    let neu = crate::konflikt::finden(basis, &hier, &datei, vault.database()?);
    let gefunden = neu.len();
    crate::konflikt::merken(&mut vault.konflikte, neu, hier, datei);
    Ok(if gefunden > 0 { vault.konflikte.len() } else { 0 })
}

/// Die offenen Konflikte — für den Dialog.
#[tauri::command]
pub fn vault_conflicts(state: tauri::State<'_, Vault>) -> Result<Vec<dto::Conflict>, String> {
    let vault = state.lock().map_err(|_| "Kern blockiert.".to_string())?;
    Ok(vault.konflikte.iter().map(|o| o.info.clone()).collect())
}

/// Entscheidet einen Konflikt: `choice` ist `hier` (die Fassung der App)
/// oder `extern` (die aus der Datei). Gespeichert wird danach wie bei jeder
/// Änderung (`vault_commit`).
#[tauri::command]
pub fn vault_conflict_resolve(state: tauri::State<'_, Vault>, id: String, choice: String) -> Result<bool, String> {
    let mut vault = state.lock().map_err(|_| "Kern blockiert.".to_string())?;
    vault.touch();
    let mut offen = std::mem::take(&mut vault.konflikte);
    let ergebnis = crate::konflikt::entscheiden(vault.database_mut()?, &mut offen, &id, &choice);
    vault.konflikte = offen;
    ergebnis.map(|_| true)
}

/// Holt Änderungen, die ein anderes Gerät in die Datei geschrieben hat.
///
/// Die Oberfläche ruft das, wenn die App wieder in den Vordergrund kommt,
/// und in Abständen, solange sie offen ist. Ist die Datei unverändert,
/// kostet das nur einen Blick aufs Änderungsdatum. Sonst wird sie
/// entschlüsselt und eingemischt; zurückgeschrieben wird nur, wenn der
/// eigene Stand etwas enthält, das der Datei fehlt — sonst schöben sich
/// zwei Geräte die Datei gegenseitig endlos zu.
///
/// `true`, wenn sich an den Einträgen etwas geändert hat.
#[tauri::command]
pub async fn vault_sync(app: tauri::AppHandle) -> Result<bool, String> {
    tauri::async_runtime::spawn_blocking(move || sync_blocking(&app))
        .await
        .map_err(|e| format!("Abgleich abgebrochen: {e}"))?
}

fn sync_blocking(app: &tauri::AppHandle) -> Result<bool, String> {
    use tauri::Manager;
    let state = app.state::<Vault>();

    // Läuft schon ein Abgleich (etwa das Nachladen nach dem Öffnen), nicht
    // darauf warten: Er meldet Änderungen selbst (`vault-merged`). Sonst
    // stand die Oberfläche, bis Nextcloud am Handy aufgab — bis zu 30 s.
    if abgleich_riegel().try_lock().is_err() {
        return Ok(false);
    }

    // Erst nachsehen, ohne den Kern festzuhalten: Lesen und Entschlüsseln
    // dauern, und so lange soll die Oberfläche weiterarbeiten können.
    let (ziel, before, seen, master, keyfile) = {
        let vault = state.lock().map_err(|_| "Kern blockiert.".to_string())?;
        let (Some(path), Some(master)) = (&vault.path, &vault.master) else { return Ok(false) };
        if vault.db.is_none() {
            return Ok(false);
        }
        // Noch nicht in der Datei: Jetzt ist eine Gelegenheit, das nachzuholen.
        if vault.ausstehend {
            drop(vault);
            let Ok(_riegel) = abgleich_riegel().try_lock() else { return Ok(false) };
            return abgleichen(app, &state).map(|_| false);
        }
        (
            path.to_string_lossy().to_string(),
            vault.opened_hash,
            vault.seen_modified,
            master.clone(),
            vault.keyfile.clone(),
        )
    };

    let modified = crate::storage::modified_ms(&ziel);
    if unveraendert_laut_datum(&ziel, modified, seen) {
        return Ok(false);
    }

    let Ok(current) = crate::storage::read(&ziel) else { return Ok(false) };
    einmischen(app, &ziel, &current, modified, before, &master, keyfile.as_deref().map(|k| k.as_slice()))
}

/// Holt nach dem Öffnen aus der Offline-Kopie den Stand vom eigentlichen
/// Ort und mischt ihn ein (siehe `vault_unlock`, „sofort aus der Kopie“).
///
/// Läuft auf einem eigenen Faden: Nextcloud fragt beim Öffnen erst seinen
/// Server, und ist der nicht erreichbar, dauert das bis zu 30 Sekunden.
fn nachladen(app: tauri::AppHandle) {
    use tauri::Manager;
    let Ok(_riegel) = abgleich_riegel().lock() else { return };
    let mut uhr = Uhr::neu();
    let state = app.state::<Vault>();
    let Some((ziel, before, master, keyfile)) = state.lock().ok().and_then(|v| {
        Some((v.path.clone()?.to_string_lossy().to_string(), v.opened_hash, v.master.clone()?, v.keyfile.clone()))
    }) else {
        return;
    };

    let current = match crate::storage::read(&ziel) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("[entsperren] Datei im Hintergrund nicht lesbar, es bleibt bei der Kopie: {err}");
            return;
        }
    };
    uhr.schritt("Datei im Hintergrund gelesen");

    match einmischen(&app, &ziel, &current, None, before, &master, keyfile.as_deref().map(|k| k.as_slice())) {
        Ok(geaendert) => {
            uhr.schritt("eingemischt");
            if geaendert {
                use tauri::Emitter;
                let _ = app.emit("vault-merged", ());
            }
        }
        Err(err) => eprintln!("[entsperren] Einmischen im Hintergrund fehlgeschlagen: {err}"),
    }
}

/// Mischt den Stand `current` vom Ort in die offene Datenbank — der Kern
/// von `vault_sync`, auch nach dem Öffnen aus der Kopie gebraucht.
fn einmischen(
    app: &tauri::AppHandle,
    ziel: &str,
    current: &[u8],
    modified: Option<i64>,
    before: Option<[u8; 32]>,
    master: &str,
    keyfile: Option<&[u8]>,
) -> Result<bool, String> {
    use tauri::Manager;
    let state = app.state::<Vault>();
    let hash = digest(current);
    if Some(hash) == before {
        if let Ok(mut vault) = state.lock() {
            vault.seen_modified = modified;
            // Die Kopie war schon der Stand der Datei.
            vault.offline = false;
        }
        return Ok(false);
    }

    let theirs = parse_with(master, keyfile, current)?;
    let basis = crate::versions::juengster(app, ziel).and_then(|b| parse_with(master, keyfile, &b).ok());

    // Der fremde Stand, bevor wir ihn einmischen: Geht beim Zusammenführen
    // etwas verloren, steht er hier noch.
    crate::versions::sichern(app, ziel, current, crate::versions::Grund::Fremd, crate::versions::abdruck(&theirs));

    let mut vault = state.lock().map_err(|_| "Kern blockiert.".to_string())?;
    // Inzwischen selbst gespeichert? Dann ist dieser Stand schon drin oder
    // wird beim nächsten Mal geholt.
    if vault.opened_hash != before || vault.db.is_none() {
        return Ok(false);
    }

    let gesehen = vault.opened_config.clone();
    einstellungen_uebernehmen(vault.database_mut()?, &theirs, gesehen.as_ref());
    let vorher = vault.database()?.clone();
    let (changed, ours_ahead) = merge(vault.database_mut()?, &theirs)?;
    let neue_konflikte = konflikte_merken(&mut vault, basis.as_ref(), vorher, theirs.clone())?;
    if neue_konflikte > 0 {
        use tauri::Emitter;
        let _ = app.emit("vault-conflicts", neue_konflikte);
    }

    if ours_ahead && !vault.read_only {
        write_back_als(app, &mut vault, ziel, crate::versions::Grund::Zusammengefuehrt)?;
    } else {
        vault.opened_config = Some(theirs.config.clone());
        vault.opened_hash = Some(hash);
        vault.seen_modified = modified;
        vault.offline = false;
        // Die Datei hat alles, was die App hat — nichts mehr nachzuholen.
        vault.ausstehend = false;
        crate::offline::store(app, ziel, current);
    }
    Ok(changed)
}

/// Darf der Blick aufs Änderungsdatum das Lesen ersparen?
///
/// Bei einem Pfad ja: Das Datum kommt vom Dateisystem, und der
/// Cloud-Client schreibt die Datei wirklich neu. Bei einer
/// `content://`-Adresse nein: Dort nennt der Anbieter das Datum seiner
/// eigenen Kopie, und die holt er — Nextcloud jedenfalls — erst beim
/// Öffnen neu vom Server. Wer sich darauf verließ, sah die Änderungen des
/// anderen Geräts nie: Das Datum blieb stehen, also wurde nie gelesen,
/// also blieb das Datum stehen.
///
/// Über eine Adresse wird deshalb immer gelesen; ob sich etwas getan hat,
/// sagt danach der Vergleich des Inhalts.
fn unveraendert_laut_datum(ziel: &str, modified: Option<i64>, seen: Option<i64>) -> bool {
    !crate::storage::is_uri(ziel) && modified.is_some() && modified == seen
}

/// Mischt `theirs` in `ours`: Einträge und Ordner werden über ihre UUID
/// einander zugeordnet, von zwei Fassungen gilt die jüngere, die ältere
/// landet im Verlauf; Löschvermerke werden beachtet. Das ist derselbe
/// Abgleich, den KeePassXC beim Zusammenführen macht.
///
/// Zurück kommt (hat sich `ours` geändert, fehlt `theirs` etwas von `ours`).
pub(crate) fn merge(ours: &mut Database, theirs: &Database) -> Result<(bool, bool), String> {
    // Erst die Zusatzangaben, dann die Einträge: Die Bibliothek führt
    // `meta.custom_data` nicht mit, und darin steht unter anderem die
    // Verknüpfung mit dem Browser. Ohne diesen Schritt warf das nächste
    // Speichern weg, was das andere Gerät dort eingetragen hatte — in der
    // Erweiterung musste man dann wieder auf „Verbinden" drücken.
    let custom = zusatzangaben(ours, theirs) | kopfangaben(ours, theirs);
    let log = zusammenfuehren(ours, theirs)?;

    // Umgekehrt noch einmal auf einer Kopie: Kommt dabei nichts heraus,
    // steht in der Datei schon alles, und sie muss nicht neu geschrieben werden.
    let mut probe = theirs.clone();
    let custom_back = zusatzangaben(&mut probe, ours) | kopfangaben(&mut probe, ours);
    let back = zusammenfuehren(&mut probe, ours)?;

    Ok((!log.events.is_empty() || custom, !back.events.is_empty() || custom_back))
}

/// Führt `meta.custom_data` von `quelle` nach `ziel` — wie beim Rest gilt
/// der jüngere Eintrag, und was dem Ziel fehlt, kommt dazu. Gelöscht wird
/// nichts: Für Zusatzangaben gibt es keine Löschvermerke, und ein
/// verlorener Schlüssel wiegt schwerer als ein übrig gebliebener.
///
/// Liefert, ob sich am Ziel etwas geändert hat.
fn zusatzangaben(ziel: &mut Database, quelle: &Database) -> bool {
    let mut geaendert = false;

    for (schluessel, fremd) in &quelle.meta.custom_data {
        match ziel.meta.custom_data.get(schluessel) {
            Some(eigen) if gleicher_wert(&eigen.value, &fremd.value) => continue,
            // Ohne Zeitstempel lässt sich nichts vergleichen; dann bleibt
            // der eigene Wert stehen, statt ihn blind zu ersetzen.
            Some(eigen) if fremd.last_modification_time <= eigen.last_modification_time => continue,
            _ => {}
        }
        ziel.meta.custom_data.insert(schluessel.clone(), fremd.clone());
        geaendert = true;
    }

    geaendert
}

/// Zwei Zusatzwerte als Text verglichen. Die Bibliothek liest Base64 als
/// `Binary` ein; derselbe Wert, eben erst als Text angelegt, gälte sonst als
/// anders — und die Datei würde ohne Not neu geschrieben.
fn gleicher_wert(a: &Option<keepass::db::CustomDataValue>, b: &Option<keepass::db::CustomDataValue>) -> bool {
    use base64::Engine as _;
    use keepass::db::CustomDataValue::{Binary, String as Text};
    let text = |v: &Option<keepass::db::CustomDataValue>| match v {
        Some(Text(t)) => Some(t.clone()),
        Some(Binary(b)) => Some(base64::engine::general_purpose::STANDARD.encode(b)),
        None => None,
    };
    text(a) == text(b)
}

/// Name und Beschreibung der Datenbank: Der jüngere gilt, wie bei den
/// Einträgen. Die Bibliothek führt beides nicht zusammen — ein in KeePassXC
/// oder auf dem Handy geänderter Name kam sonst beim nächsten Speichern
/// wieder zurück.
fn kopfangaben(ziel: &mut Database, quelle: &Database) -> bool {
    let mut geaendert = false;
    let (z, q) = (&mut ziel.meta, &quelle.meta);
    if q.database_name_changed > z.database_name_changed && q.database_name != z.database_name {
        z.database_name = q.database_name.clone();
        z.database_name_changed = q.database_name_changed;
        geaendert = true;
    }
    if q.database_description_changed > z.database_description_changed
        && q.database_description != z.database_description
    {
        z.database_description = q.database_description.clone();
        z.database_description_changed = q.database_description_changed;
        geaendert = true;
    }
    geaendert
}

/// Verschlüsselung, Schlüsselableitung und Kompression der Datei.
///
/// Die stehen nicht in den Einträgen, sondern im Kopf der Datei, und
/// `merge` fasst sie nicht an. Geschrieben wurde deshalb immer mit dem, was
/// beim Öffnen galt: Stellte ein anderes Programm (KeePassXC, eine App auf
/// dem Handy) die Verschlüsselung um, machte das nächste Speichern hier es
/// wieder rückgängig.
///
/// Jetzt gilt: Steht in der Datei etwas anderes als beim letzten Lesen oder
/// Schreiben (`gesehen`), hat jemand anderes umgestellt — das wird
/// übernommen. Außer es wurde auch hier umgestellt (Einstellungen →
/// Sicherheit); dann gilt das eigene, denn das ist die jüngere Absicht.
fn einstellungen_uebernehmen(ours: &mut Database, theirs: &Database, gesehen: Option<&keepass::config::DatabaseConfig>) -> bool {
    let Some(gesehen) = gesehen else { return false };
    let fremd_umgestellt = theirs.config != *gesehen;
    let hier_umgestellt = ours.config != *gesehen;
    if fremd_umgestellt && !hier_umgestellt {
        ours.config = theirs.config.clone();
        return true;
    }
    false
}

/// `ours.merge(theirs)` — mit einem Ausweg für denselben Zeitpunkt.
///
/// Die Bibliothek entscheidet nach der Änderungszeit, auf die Sekunde. Haben
/// beide Seiten denselben Eintrag in derselben Sekunde verschieden geändert,
/// bricht sie ab — und mit ihr der ganze Abgleich. Dann gilt die Fassung der
/// App (eine Sekunde jünger gemacht); dass beide Seiten ihn geändert haben,
/// meldet danach die Konfliktsuche, und der Nutzer entscheidet.
///
/// Zusammengeführt wird auf einer Kopie: Was die Bibliothek bis zum Abbruch
/// schon geändert hat, soll nicht im Stand der App stehen bleiben.
fn zusammenfuehren(ours: &mut Database, theirs: &Database) -> Result<keepass::db::merge::MergeLog, String> {
    use keepass::db::merge::MergeError;
    for _ in 0..64 {
        let mut probe = ours.clone();
        match probe.merge(theirs) {
            Ok(log) => {
                *ours = probe;
                return Ok(log);
            }
            Err(MergeError::EntryModificationTimeNotUpdated(id)) => {
                let mut eintrag = ours.entry_mut(id).ok_or_else(|| merge_error(MergeError::EntryModificationTimeNotUpdated(id)))?;
                let zeit = eintrag.times.last_modification.unwrap_or_else(keepass::db::Times::now);
                eintrag.times.last_modification = Some(zeit + chrono::Duration::seconds(1));
            }
            Err(e) => return Err(merge_error(e)),
        }
    }
    Err("Zu viele Einträge mit derselben Änderungszeit — es wurde nichts zusammengeführt.".into())
}

fn merge_error(e: keepass::db::merge::MergeError) -> String {
    format!(
        "Die Datei wurde auf einem anderen Gerät geändert und lässt sich nicht mit diesem \
         Stand zusammenführen ({e}). Es wurde nichts geschrieben."
    )
}

/// Entschlüsselt die Datei, wie sie gerade auf der Platte liegt, mit dem
/// Schlüssel der offenen Datenbank.
fn parse_foreign(vault: &crate::state::VaultState, bytes: &[u8]) -> Result<Database, String> {
    let master = vault.master.as_ref().ok_or("Kein Master-Passwort im Kern.")?;
    parse_with(master, vault.keyfile.as_deref().map(|k| k.as_slice()), bytes)
}

fn parse_with(master: &str, keyfile: Option<&[u8]>, bytes: &[u8]) -> Result<Database, String> {
    Database::parse(bytes, key_of(master, keyfile)?).map_err(|e| match e {
        keepass::error::DatabaseOpenError::Key(_) => "Die Datei wurde auf einem anderen Gerät \
            geändert und lässt sich mit dem bisherigen Master-Passwort nicht mehr öffnen — \
            vermutlich wurde es dort geändert. Es wurde nichts geschrieben. Sperre die \
            Datenbank und öffne sie mit dem neuen Passwort."
            .to_string(),
        other => format!("Die geänderte Datei ist nicht lesbar: {other}. Es wurde nichts geschrieben."),
    })
}

/// Master-Passwort plus, falls vorhanden, Schlüsseldatei.
fn key_of(master: &str, keyfile: Option<&[u8]>) -> Result<DatabaseKey, String> {
    let mut key = DatabaseKey::new();
    if !master.is_empty() {
        key = key.with_password(master);
    }
    if let Some(mut bytes) = keyfile {
        key = key
            .with_keyfile(&mut bytes)
            .map_err(|e| format!("Schlüsseldatei nicht verwendbar: {e}"))?;
    }
    Ok(key)
}

/// Verschlüsselt den Stand im Kern und schreibt ihn an `ziel`.
///
/// `grund` sagt, als was der Stand bei den Versionen steht: gespeichert
/// oder zusammengeführt.
fn write_back_als(
    app: &tauri::AppHandle,
    vault: &mut crate::state::VaultState,
    ziel: &str,
    grund: crate::versions::Grund,
) -> Result<(), String> {
    let master = vault.master.as_ref().ok_or("Kein Master-Passwort im Kern.")?;
    let key = key_of(master, vault.keyfile.as_deref().map(|k| k.as_slice()))?;

    let mut bytes: Vec<u8> = Vec::new();
    vault
        .database()?
        .save(&mut bytes, key)
        .map_err(|e| format!("Verschlüsseln fehlgeschlagen: {e}"))?;

    crate::storage::write(ziel, &bytes)?;
    spur("geschrieben", &bytes, Some(vault.database()?));
    let abdruck = crate::versions::abdruck(vault.database()?);
    crate::versions::sichern(app, ziel, &bytes, grund, abdruck);

    // Ab jetzt ist unser eigener Stand der maßgebliche.
    vault.opened_config = Some(vault.database()?.config.clone());
    vault.opened_hash = Some(digest(&bytes));
    vault.seen_modified = crate::storage::modified_ms(ziel);
    vault.offline = false;
    vault.ausstehend = false;
    crate::offline::store(app, ziel, &bytes);
    Ok(())
}

/// Sagt verbundenen Browsern, dass die Datenbank zu oder offen ist, und
/// beendet beim Sperren die Schonfrist des Autofill-Dienstes.
///
/// Die Browser-Anbindung gibt es nur auf dem Desktop, den Dienst nur auf
/// Android — jede Seite kennt hier nur ihre eigene Hälfte.
fn browser_announce(locked: bool) {
    #[cfg(desktop)]
    crate::keepass_extension::api::announce(locked);

    #[cfg(target_os = "android")]
    if locked {
        crate::android_services::nach_sperren();
    }

    #[cfg(not(desktop))]
    let _ = locked;
}

#[tauri::command]
pub fn vault_lock(state: tauri::State<'_, Vault>) -> Result<bool, String> {
    state.lock().map_err(|_| "Kern blockiert.".to_string())?.clear();
    browser_announce(true);
    Ok(true)
}

/// Meldet dem Kern, dass die Oberfläche benutzt wird. Ohne das würde die
/// Selbstsperre auch beim Lesen zuschlagen — Scrollen und Suchen lösen
/// keinen Kommandoaufruf aus.
#[tauri::command]
pub fn vault_touch(state: tauri::State<'_, Vault>) -> Result<bool, String> {
    state.lock().map_err(|_| "Kern blockiert.".to_string())?.touch();
    Ok(true)
}

/// Setzt die Ruhezeit neu — die Oberfläche ruft das, wenn die Einstellung
/// geändert wird. `0` schaltet die Selbstsperre ab.
#[tauri::command]
pub fn vault_set_auto_lock(
    state: tauri::State<'_, Vault>,
    minutes: u64,
) -> Result<bool, String> {
    let mut vault = state.lock().map_err(|_| "Kern blockiert.".to_string())?;
    vault.auto_lock_minutes = minutes;
    vault.touch();
    Ok(true)
}

/// Wächter: sperrt die Datenbank, wenn zu lange nichts passiert ist.
///
/// Das gehört in den Kern und nicht in den Webview — ein Timer im Fenster
/// läuft nicht zuverlässig weiter, wenn das Fenster im Hintergrund liegt
/// oder der Rechner schläft. Hier zählt die Uhr in jedem Fall.
pub fn start_auto_lock(app: tauri::AppHandle) {
    use tauri::{Emitter, Manager};

    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(20));

        let Some(state) = app.try_state::<Vault>() else { continue };
        let Ok(mut vault) = state.lock() else { continue };

        if vault.idle_expired() {
            vault.clear();
            drop(vault);
            browser_announce(true);
            // Die Oberfläche zeigt daraufhin den Sperrbildschirm.
            let _ = app.emit("vault-locked", "Wegen Untätigkeit gesperrt.");
        }
    });
}

/* =========================================================
   Gemeinsam genutzt
   ========================================================= */

/// Findet einen Eintrag über seine UUID als Zeichenkette.
pub fn entry_id_of(db: &Database, uuid: &str) -> Option<keepass::db::EntryId> {
    db.iter_all_entries()
        .find(|e| e.id().uuid().to_string() == uuid)
        .map(|e| e.id())
}

/// Setzt alle nicht geschützten Felder eines Eintrags.
pub fn apply_plain_fields(entry: &mut keepass::db::EntryMut<'_>, input: &dto::Entry) {
    use keepass::db::fields;

    entry.set_unprotected(fields::TITLE, input.name.clone());
    entry.set_unprotected(fields::USERNAME, input.username.clone());
    entry.set_unprotected(fields::URL, input.url.clone());
    entry.set_unprotected(fields::NOTES, input.notes.clone());

    entry.tags = input.tags.clone();
    entry.times.last_modification = Some(keepass::db::Times::now());

    match &input.expires {
        Some(day) => {
            entry.times.expires = Some(true);
            entry.times.expiry = NaiveDateTime::parse_from_str(
                &format!("{day} 00:00:00"),
                "%Y-%m-%d %H:%M:%S",
            )
            .ok();
        }
        None => entry.times.expires = Some(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepass::db::{fields, EntryId, Value};

    fn am(tag: u32) -> NaiveDateTime {
        chrono::NaiveDate::from_ymd_opt(2026, 1, tag).unwrap().and_hms_opt(12, 0, 0).unwrap()
    }

    fn add(db: &mut Database, title: &str, attachment: Option<&[u8]>) -> EntryId {
        let root = db.root().id();
        let id = db.group_mut(root).unwrap().add_entry().id();
        let mut e = db.entry_mut(id).unwrap();
        e.set_unprotected(fields::TITLE, title);
        if let Some(data) = attachment {
            e.add_attachment(format!("{title}.bin"), Value::Unprotected(data.to_vec()));
        }
        e.times.last_modification = Some(am(1));
        e.times.location_changed = Some(am(1));
        id
    }

    fn roundtrip(db: &Database) -> Database {
        let mut bytes = Vec::new();
        db.save(&mut bytes, key_of("test", None).unwrap()).unwrap();
        parse_with("test", None, &bytes).unwrap()
    }

    fn title(db: &Database, id: EntryId) -> String {
        db.entry(id).unwrap().get(fields::TITLE).unwrap_or_default().to_string()
    }

    fn attachment(db: &Database, id: EntryId) -> Vec<Vec<u8>> {
        db.entry(id).unwrap().attachments().map(|a| a.data.get().to_vec()).collect()
    }

    fn edit(db: &mut Database, id: EntryId, new_title: &str, when: NaiveDateTime) {
        let mut e = db.entry_mut(id).unwrap();
        e.set_unprotected(fields::TITLE, new_title);
        e.times.last_modification = Some(when);
    }

    /// Zwei Geräte ändern dieselbe Datei, jedes an einer anderen Stelle —
    /// nach dem Abgleich steht beides drin, auch die Anhänge.
    #[test]
    fn zwei_geraete_werden_zusammengefuehrt() {
        let mut base = Database::new();
        let a = add(&mut base, "A", Some(b"anhang a"));
        let b = add(&mut base, "B", None);
        let weg = add(&mut base, "Weg", None);
        let bild = add(&mut base, "Bild", Some(b"alt"));
        let base = roundtrip(&base);

        // Gerät 1: A umbenannt, C mit Anhang neu.
        let mut eins = base.clone();
        edit(&mut eins, a, "A neu", am(2));
        let c = add(&mut eins, "C", Some(b"anhang c"));

        // Gerät 2: B umbenannt, D mit Anhang neu, „Weg" gelöscht,
        // Anhang von „Bild" ersetzt.
        let mut zwei = base.clone();
        edit(&mut zwei, b, "B neu", am(3));
        let d = add(&mut zwei, "D", Some(b"anhang d"));
        zwei.entry_mut(weg).unwrap().track_changes().remove();
        {
            let mut e = zwei.entry_mut(bild).unwrap();
            e.remove_attachment_by_name("Bild.bin");
            e.add_attachment("Bild.bin", Value::Unprotected(b"neu".to_vec()));
            e.times.last_modification = Some(am(4));
        }
        let datei = roundtrip(&zwei);

        let (changed, ahead) = merge(&mut eins, &datei).unwrap();
        assert!(changed && ahead);

        let ergebnis = roundtrip(&eins);
        assert_eq!(title(&ergebnis, a), "A neu");
        assert_eq!(title(&ergebnis, b), "B neu");
        assert_eq!(attachment(&ergebnis, a), vec![b"anhang a".to_vec()]);
        assert_eq!(attachment(&ergebnis, c), vec![b"anhang c".to_vec()]);
        assert_eq!(attachment(&ergebnis, d), vec![b"anhang d".to_vec()]);
        assert_eq!(attachment(&ergebnis, bild), vec![b"neu".to_vec()]);
        assert!(ergebnis.entry(weg).is_none());

        // Das andere Gerät holt sich den gemeinsamen Stand und hat danach
        // nichts mehr, was der Datei fehlt — es schreibt nicht zurück.
        let mut zwei = datei;
        let (changed, ahead) = merge(&mut zwei, &ergebnis).unwrap();
        assert!(changed && !ahead);

        let (changed, ahead) = merge(&mut zwei, &ergebnis).unwrap();
        assert!(!changed && !ahead);
    }

    /// Beide ändern denselben Eintrag: Der jüngere Stand gilt, der ältere
    /// bleibt im Verlauf.
    #[test]
    fn juengere_aenderung_gewinnt() {
        let mut base = Database::new();
        let a = add(&mut base, "A", None);
        let base = roundtrip(&base);

        let mut eins = base.clone();
        edit(&mut eins, a, "von Gerät 1", am(2));
        let mut zwei = base;
        edit(&mut zwei, a, "von Gerät 2", am(3));

        merge(&mut eins, &roundtrip(&zwei)).unwrap();
        let ergebnis = roundtrip(&eins);
        assert_eq!(title(&ergebnis, a), "von Gerät 2");

        let verlauf: Vec<String> = ergebnis
            .entry(a)
            .unwrap()
            .history
            .as_ref()
            .map(|h| h.get_entries().iter().filter_map(|e| e.get(fields::TITLE).map(str::to_string)).collect())
            .unwrap_or_default();
        assert!(verlauf.contains(&"von Gerät 1".to_string()), "{verlauf:?}");
    }

    /// Die Verknüpfung mit dem Browser steht in `meta.custom_data`. Geht sie
    /// beim Speichern verloren, muss man in der Erweiterung jedes Mal wieder
    /// auf „Verbinden" drücken — genau das war die Klage.
    #[test]
    fn verknuepfung_ueberlebt_das_speichern() {
        use keepass::db::{CustomDataItem, CustomDataValue};

        let mut db = Database::new();
        db.meta.custom_data.insert(
            "KPXC_BROWSER WKeePass abc".to_string(),
            CustomDataItem {
                value: Some(CustomDataValue::String("schluessel-123".into())),
                last_modification_time: None,
            },
        );

        let wieder = roundtrip(&db);
        let gespeichert = wieder
            .meta
            .custom_data
            .get("KPXC_BROWSER WKeePass abc")
            .and_then(|i| i.value.as_ref());

        assert!(
            matches!(gespeichert, Some(CustomDataValue::String(s)) if s == "schluessel-123"),
            "Verknüpfung nach dem Speichern: {gespeichert:?}"
        );
    }

    /// Das andere Gerät hat die Verknüpfung in die Datei geschrieben. Beim
    /// Zusammenführen muss sie herüberkommen — sonst wirft das nächste
    /// Speichern von hier aus die Verknüpfung des anderen Geräts wieder weg.
    #[test]
    fn verknuepfung_kommt_beim_zusammenfuehren_mit() {
        use keepass::db::{CustomDataItem, CustomDataValue};

        let mut base = Database::new();
        add(&mut base, "A", None);
        let base = roundtrip(&base);

        // Das andere Gerät verknüpft einen Browser.
        let mut fremd = base.clone();
        fremd.meta.custom_data.insert(
            "KPXC_BROWSER WKeePass abc".to_string(),
            CustomDataItem {
                value: Some(CustomDataValue::String("schluessel-123".into())),
                last_modification_time: Some(am(2)),
            },
        );
        let datei = roundtrip(&fremd);

        // Wir kennen sie noch nicht.
        let mut unser = base;
        merge(&mut unser, &datei).unwrap();

        let nachher = unser
            .meta
            .custom_data
            .get("KPXC_BROWSER WKeePass abc")
            .and_then(|i| i.value.as_ref());
        assert!(
            matches!(nachher, Some(CustomDataValue::String(s)) if s == "schluessel-123"),
            "Verknüpfung nach dem Zusammenführen: {nachher:?}"
        );
    }

    /// Beide Seiten kennen denselben Schlüssel mit verschiedenem Wert: Der
    /// jüngere gilt, in beide Richtungen — und ohne Zeitstempel bleibt der
    /// eigene stehen, statt blind ersetzt zu werden.
    /// Ein anderes Programm stellt die Schlüsselableitung um: Das nächste
    /// Speichern hier übernimmt das, statt es zurückzudrehen. Wurde auch hier
    /// umgestellt, bleibt es beim eigenen.
    #[test]
    fn fremd_umgestellte_verschluesselung_bleibt() {
        use keepass::config::KdfConfig;
        let stufe = |iterations| KdfConfig::Argon2id { iterations, memory: 1 << 20, parallelism: 1, version: Default::default() };

        let mut ours = Database::new();
        ours.config.kdf_config = stufe(2);
        let gesehen = ours.config.clone();
        let mut theirs = ours.clone();
        theirs.config.kdf_config = stufe(9);

        assert!(einstellungen_uebernehmen(&mut ours, &theirs, Some(&gesehen)));
        assert_eq!(ours.config.kdf_config, stufe(9));

        let mut eigen = Database::new();
        eigen.config.kdf_config = stufe(5);
        assert!(!einstellungen_uebernehmen(&mut eigen, &theirs, Some(&gesehen)), "hier umgestellt: bleibt");
        assert_eq!(eigen.config.kdf_config, stufe(5));
    }

    /// „Standard“ muss am iPhone/iPad beim Ausfüllen über die Tastatur
    /// aufgehen: höchstens 16 MiB. Und neue Dateien bekommen eine Stufe,
    /// nicht die Voreinstellung der Bibliothek (Argon2d, 1 MiB).
    #[test]
    fn standard_passt_aufs_ipad() {
        use keepass::config::KdfConfig;
        let mut db = Database::new();
        stufe_setzen(&mut db, "standard").unwrap();
        let KdfConfig::Argon2id { iterations, memory, parallelism, .. } = db.config.kdf_config else { panic!("kein Argon2id") };
        assert!(memory <= 16 * 1024 * 1024);
        assert_eq!(stufe_von(iterations, memory / (1024 * 1024), parallelism), "standard");
        // Die früheren Stufen 10 × 64, 14 × 128, 20 × 256 werden weiter erkannt.
        assert_eq!(stufe_von(10, 64, 4), "erhoeht");
        assert_eq!(stufe_von(20, 256, 4), "stark");
        assert!(stufe_setzen(&mut db, "gibtsnicht").is_err());
    }

    /// Ein anderswo umbenannter Tresor behält seinen neuen Namen.
    #[test]
    fn juengerer_name_gilt() {
        let mut ours = Database::new();
        ours.meta.database_name = Some("Alt".into());
        ours.meta.database_name_changed = Some(am(1));
        let mut theirs = ours.clone();
        theirs.meta.database_name = Some("Neu".into());
        theirs.meta.database_name_changed = Some(am(5));

        let (geaendert, _) = merge(&mut ours, &theirs).unwrap();
        assert!(geaendert);
        assert_eq!(ours.meta.database_name.as_deref(), Some("Neu"));
    }

    #[test]
    fn bei_zusatzangaben_gilt_die_juengere() {
        use keepass::db::{CustomDataItem, CustomDataValue};

        let angabe = |wert: &str, wann: Option<NaiveDateTime>| CustomDataItem {
            value: Some(CustomDataValue::String(wert.into())),
            last_modification_time: wann,
        };
        let wert = |db: &Database| match db.meta.custom_data.get("k").and_then(|i| i.value.clone()) {
            Some(CustomDataValue::String(s)) => s,
            anderes => panic!("unerwartet: {anderes:?}"),
        };

        let mut alt = Database::new();
        alt.meta.custom_data.insert("k".into(), angabe("alt", Some(am(1))));
        let mut neu = Database::new();
        neu.meta.custom_data.insert("k".into(), angabe("neu", Some(am(5))));

        // Das Jüngere kommt herein …
        let mut ziel = alt.clone();
        assert!(zusatzangaben(&mut ziel, &neu));
        assert_eq!(wert(&ziel), "neu");

        // … das Ältere verdrängt nichts.
        let mut ziel = neu.clone();
        assert!(!zusatzangaben(&mut ziel, &alt));
        assert_eq!(wert(&ziel), "neu");

        // Ohne Zeitstempel bleibt der eigene Wert.
        let mut eigen = Database::new();
        eigen.meta.custom_data.insert("k".into(), angabe("eigen", None));
        let mut fremd = Database::new();
        fremd.meta.custom_data.insert("k".into(), angabe("fremd", None));
        assert!(!zusatzangaben(&mut eigen, &fremd));
        assert_eq!(wert(&eigen), "eigen");
    }

    /// Das Änderungsdatum spart das Lesen nur bei echten Pfaden. Über eine
    /// Adresse vom Handy wird immer gelesen — sonst kommen die Änderungen
    /// des anderen Geräts nie an.
    #[test]
    fn datum_spart_das_lesen_nur_bei_pfaden() {
        let pfad = "/home/du/passwoerter.kdbx";
        let adresse = "content://org.nextcloud.documents/document/abc";

        assert!(unveraendert_laut_datum(pfad, Some(100), Some(100)));
        assert!(!unveraendert_laut_datum(pfad, Some(200), Some(100)), "neueres Datum: lesen");
        assert!(!unveraendert_laut_datum(pfad, None, None), "ohne Datum: lesen");

        assert!(!unveraendert_laut_datum(adresse, Some(100), Some(100)), "Adresse: immer lesen");
        assert!(!unveraendert_laut_datum(adresse, None, None));
    }
}

/// Der ganze Weg mit echtem AppHandle und echten Dateien: öffnen,
/// ändern, in die eigene Kopie und in die Datei schreiben, die Datei von
/// außen ändern (wie ein anderes Gerät), zusammenführen, Konflikt
/// entscheiden, aus der Kopie wieder öffnen und nachladen.
#[cfg(all(test, desktop))]
mod ablauf {
    use super::*;
    use tauri::Manager;

    const PW: &str = "geheim";

    fn schluessel() -> DatabaseKey {
        DatabaseKey::new().with_password(PW)
    }

    fn lesen(pfad: &std::path::Path) -> Database {
        Database::parse(&std::fs::read(pfad).unwrap(), schluessel()).unwrap()
    }

    fn schreiben(pfad: &std::path::Path, db: &Database) {
        let mut bytes = Vec::new();
        db.save(&mut bytes, schluessel()).unwrap();
        std::fs::write(pfad, bytes).unwrap();
    }

    fn neu(db: &mut Database, titel: &str) -> String {
        let mut wurzel = db.root_mut();
        let mut e = wurzel.add_entry();
        e.set_unprotected("Title", titel);
        e.id().uuid().to_string()
    }

    fn setzen(db: &mut Database, uuid: &str, feld: &str, wert: &str, sek: i64) {
        let id = db.iter_all_entries().find(|e| e.id().uuid().to_string() == uuid).unwrap().id();
        let mut e = db.entry_mut(id).unwrap();
        e.set_unprotected(feld.to_string(), wert);
        e.times.last_modification = Some(keepass::db::Times::now() + chrono::Duration::seconds(sek));
    }

    fn feld(db: &Database, uuid: &str, feld: &str) -> Option<String> {
        db.iter_all_entries()
            .find(|e| e.id().uuid().to_string() == uuid)
            .map(|e| e.get(feld).unwrap_or_default().to_string())
    }

    fn titel(db: &Database) -> Vec<String> {
        let mut t: Vec<String> = db.iter_all_entries().map(|e| e.get_title().unwrap_or_default().to_string()).collect();
        t.sort();
        t
    }

    /// Wartet, bis `fertig` gilt — die Abgleiche laufen auf eigenen Fäden.
    fn warten(app: &tauri::AppHandle, fertig: impl Fn(&crate::state::VaultState) -> bool) {
        for _ in 0..200 {
            if app.state::<Vault>().lock().is_ok_and(|v| fertig(&v)) {
                // Den Riegel einmal nehmen: Ein laufender Abgleich ist dann fertig.
                drop(abgleich_riegel().lock());
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        panic!("Zeitüberschreitung");
    }

    #[test]
    fn kopie_abgleich_konflikt() {
        let tmp = std::env::temp_dir().join(format!("wkeepass-ablauf-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        // Datenverzeichnis der Probe-App (Offline-Kopie, Versionen) in den Test.
        std::env::set_var("XDG_DATA_HOME", tmp.join("data"));
        std::env::set_var("XDG_CONFIG_HOME", tmp.join("config"));

        // Eine echte App, aber ohne Fenster: Es soll nichts auf dem
        // Bildschirm erscheinen. Ohne Anzeige (CI) geht es nicht.
        if std::env::var_os("WAYLAND_DISPLAY").is_none() && std::env::var_os("DISPLAY").is_none() {
            eprintln!("übersprungen: keine Anzeige");
            return;
        }
        let mut kontext: tauri::Context<tauri::Wry> = tauri::generate_context!();
        kontext.config_mut().app.windows.clear();
        let app = tauri::Builder::default()
            .any_thread()
            .manage(Vault::default())
            .build(kontext)
            .unwrap();
        let h = app.handle().clone();
        let datei = tmp.join("tresor.kdbx");
        let pfad = datei.to_string_lossy().to_string();

        // Ausgangslage: Eintrag A in der Datei.
        let mut db = Database::new();
        let a = neu(&mut db, "A");
        schreiben(&datei, &db);

        let entsperren = |h: &tauri::AppHandle| {
            tauri::async_runtime::block_on(vault_unlock(
                h.clone(), h.state::<Vault>(), pfad.clone(), "password".into(), Some(PW.into()), None, Some(0), None,
            ))
            .unwrap();
        };

        // 1. Öffnen (noch keine eigene Kopie: von der Datei), ändern, speichern.
        entsperren(&h);
        std::thread::sleep(std::time::Duration::from_millis(300));
        {
            let state = h.state::<Vault>();
            let mut v = state.lock().unwrap();
            setzen(v.database_mut().unwrap(), &a, "URL", "https://erst", 5);
        }
        commit(&h, &h.state::<Vault>()).unwrap();
        // Sofort in der eigenen Kopie …
        let kopie = crate::offline::kopie(&h, &pfad).expect("eigene Kopie");
        assert_eq!(feld(&Database::parse(&kopie, schluessel()).unwrap(), &a, "URL").as_deref(), Some("https://erst"));
        // … und im Hintergrund in der Datei.
        warten(&h, |v| !v.ausstehend);
        assert_eq!(feld(&lesen(&datei), &a, "URL").as_deref(), Some("https://erst"));

        // 2. Das Beispiel: extern zwei neue Einträge und A geändert, hier
        //    einer neu und A anders geändert.
        let mut fremd = lesen(&datei);
        neu(&mut fremd, "Extern 1");
        neu(&mut fremd, "Extern 2");
        setzen(&mut fremd, &a, "UserName", "extern", 40);
        schreiben(&datei, &fremd);
        {
            let state = h.state::<Vault>();
            let mut v = state.lock().unwrap();
            let db = v.database_mut().unwrap();
            neu(db, "Hier");
            setzen(db, &a, "Notes", "hier", 30);
        }
        commit(&h, &h.state::<Vault>()).unwrap();
        warten(&h, |v| !v.ausstehend);

        let jetzt = lesen(&datei);
        assert_eq!(titel(&jetzt), vec!["A", "Extern 1", "Extern 2", "Hier"], "beide Seiten in der Datei");
        let konflikte = vault_conflicts(h.state::<Vault>()).unwrap();
        assert_eq!(konflikte.len(), 1, "A wurde auf beiden Seiten geändert");
        assert_eq!(konflikte[0].id, a);
        assert_eq!(konflikte[0].winner, "extern", "die jüngere Fassung gilt bis zur Wahl");

        // Der zusammengeführte Stand nennt jede Änderung mit Herkunft.
        let staende = vault_versions(h.clone(), h.state::<Vault>()).unwrap();
        assert_eq!(staende[0].reason, "Zusammengeführt");
        let schritt = tauri::async_runtime::block_on(vault_version_step(h.clone(), h.state::<Vault>(), staende[0].id.clone())).unwrap();
        let herkunft = |name: &str| schritt.changes.iter().find(|c| c.name == name).and_then(|c| c.origin.clone());
        assert_eq!(herkunft("Extern 1").as_deref(), Some("extern"));
        assert_eq!(herkunft("Hier").as_deref(), Some("hier"));
        // A: Im Stand steht die jüngere Fassung aus der Datei; die eigene
        // Änderung wartet im Konflikt auf die Entscheidung.
        assert_eq!(herkunft("A").as_deref(), Some("extern"));

        // 3. Konflikt entscheiden: meine Fassung von A.
        vault_conflict_resolve(h.state::<Vault>(), a.clone(), "hier".into()).unwrap();
        commit(&h, &h.state::<Vault>()).unwrap();
        warten(&h, |v| !v.ausstehend);
        let jetzt = lesen(&datei);
        assert_eq!(feld(&jetzt, &a, "Notes").as_deref(), Some("hier"));
        assert_eq!(feld(&jetzt, &a, "UserName").as_deref(), Some(""));
        assert!(vault_conflicts(h.state::<Vault>()).unwrap().is_empty());

        // 4. Sperren, die Datei ändert sich von außen, wieder öffnen: sofort
        //    aus der Kopie, der neue Eintrag kommt im Hintergrund dazu.
        vault_lock(h.state::<Vault>()).unwrap();
        let mut fremd = lesen(&datei);
        neu(&mut fremd, "Später extern");
        schreiben(&datei, &fremd);
        entsperren(&h);
        warten(&h, |v| !v.offline);
        let titel_jetzt = titel(h.state::<Vault>().lock().unwrap().database().unwrap());
        assert!(titel_jetzt.contains(&"Später extern".to_string()), "nachgeladen: {titel_jetzt:?}");

        // 5. Selbstsperre: Der TOTP-Takt der Oberfläche (jede Sekunde) und
        //    der Abgleich im Hintergrund zählen nicht als Nutzung.
        let lange_her = std::time::Instant::now() - std::time::Duration::from_secs(3600);
        {
            let state = h.state::<Vault>();
            let mut v = state.lock().unwrap();
            v.auto_lock_minutes = 5;
            v.last_activity = Some(lange_her);
            v.secrets.insert("t".into(), zeroize::Zeroizing::new("JBSWY3DPEHPK3PXP".into()));
        }
        crate::secrets::vault_totp(h.state::<Vault>(), "t".into(), dto::TotpConfig::default()).unwrap();
        h.state::<Vault>().lock().unwrap().ausstehend = true;
        abgleichen(&h, &h.state::<Vault>()).unwrap();
        assert!(h.state::<Vault>().lock().unwrap().idle_expired(), "Takt und Abgleich halten die Sperre nicht auf");

        let _ = std::fs::remove_dir_all(&tmp);
    }
}

