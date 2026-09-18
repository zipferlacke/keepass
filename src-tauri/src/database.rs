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

    let Opened { db, raw, master, keyfile, format, read_only, offline } =
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

    let mut vault = state.lock().map_err(|_| "Kern blockiert.".to_string())?;
    vault.clear();
    vault.db = Some(db);
    vault.path = Some(path.clone().into());
    vault.master = Some(master);
    vault.keyfile = keyfile;
    vault.opened_hash = Some(digest(&raw));
    vault.seen_modified = crate::storage::modified_ms(&path);
    vault.read_only = read_only;
    vault.offline = offline.is_some();
    vault.auto_lock_minutes = auto_lock_minutes;
    vault.touch();

    drop(vault);

    // Entsperrt wird nicht mehr nur im Hauptfenster: Fragt ein Browser an,
    // während die Datei zu ist, geht die Anmeldemaske im kleinen Fenster auf.
    // Ohne diese Nachricht bliebe ein danebenstehendes Hauptfenster auf dem
    // Sperrbildschirm hängen, obwohl die Datenbank längst offen ist.
    use tauri::Emitter;
    let _ = app.emit("vault-unlocked", &name);

    // Was Autofill während der Sperre speichern wollte, jetzt eintragen.
    #[cfg(target_os = "android")]
    crate::android_services::nach_entsperren(&app);

    if let Some(note) = pin_note {
        return Err(format!("Geöffnet, aber die Freigabe wurde nicht gespeichert: {note}"));
    }

    let (cached_at, offline_reason) = offline.unzip();
    Ok(dto::DatabaseInfo { name, path, read_only, format, cached_at, offline_reason })
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
    let (raw, source) = crate::offline::read(app, path)?;

    let db = Database::parse(&raw, key).map_err(|e| match e {
        keepass::error::DatabaseOpenError::Key(_) => {
            "Falsches Passwort oder falsche Schlüsseldatei.".to_string()
        }
        other => format!("Datenbank konnte nicht geöffnet werden: {other}"),
    })?;

    // Zurückschreiben kann die Bibliothek nur KDBX 4.1.
    let format = db.config.version.to_string();
    let read_only = !matches!(db.config.version, keepass::config::DatabaseVersion::KDB4(1));

    // Erst nach dem Entschlüsseln kopieren: So landet nur eine Datei im
    // Zwischenspeicher, die sich mit diesem Schlüssel auch öffnen lässt.
    let offline = match source {
        crate::offline::Source::Original => {
            crate::offline::store(app, path, &raw);
            None
        }
        crate::offline::Source::Cached { saved_at, reason } => Some((saved_at, reason)),
    };

    Ok(Opened { db, raw, master, keyfile, format, read_only, offline })
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
   Öffnen. Deshalb drei Stufen statt einer Zahl.
   ========================================================= */

/// Die drei Stufen: (Durchgänge, Speicher in MiB, Fäden).
const STUFEN: [(&str, u64, u64, u32); 3] = [
    ("schnell", 5, 32, 2),
    ("standard", 10, 64, 4),
    ("stark", 20, 256, 4),
];

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
    use keepass::config::KdfConfig;

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

    // Geöffnet ist nur die Offline-Kopie. Zurückschreiben geht erst, wenn
    // die Datei wieder lesbar ist — sonst entstünde am Ort womöglich eine
    // neue Datei neben einer, die gerade nur nicht erreichbar ist.
    let current = crate::storage::read(&ziel);
    if vault.offline && current.is_err() {
        return Err(
            "Der Speicherort ist gerade nicht erreichbar — geöffnet ist die Offline-Kopie. \
             Gespeichert werden kann erst, wenn die Datei wieder da ist."
                .into(),
        );
    }

    let mut merged = false;
    if let Ok(current) = current {
        if vault.opened_hash != Some(digest(&current)) {
            let theirs = parse_foreign(&vault, &current)?;
            merged = merge(vault.database_mut()?, &theirs)?.0;
        }
    }

    write_back(app, &mut vault, &ziel)?;
    drop(vault);

    if merged {
        use tauri::Emitter;
        let _ = app.emit("vault-merged", ());
    }
    Ok(true)
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

    // Erst nachsehen, ohne den Kern festzuhalten: Lesen und Entschlüsseln
    // dauern, und so lange soll die Oberfläche weiterarbeiten können.
    let (ziel, before, seen, master, keyfile) = {
        let vault = state.lock().map_err(|_| "Kern blockiert.".to_string())?;
        let (Some(path), Some(master)) = (&vault.path, &vault.master) else { return Ok(false) };
        if vault.db.is_none() {
            return Ok(false);
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
    if modified.is_some() && modified == seen {
        return Ok(false);
    }

    let Ok(current) = crate::storage::read(&ziel) else { return Ok(false) };
    let hash = digest(&current);
    if Some(hash) == before {
        if let Ok(mut vault) = state.lock() {
            vault.seen_modified = modified;
        }
        return Ok(false);
    }

    let theirs = parse_with(&master, keyfile.as_deref().map(|k| k.as_slice()), &current)?;

    let mut vault = state.lock().map_err(|_| "Kern blockiert.".to_string())?;
    // Inzwischen selbst gespeichert? Dann ist dieser Stand schon drin oder
    // wird beim nächsten Mal geholt.
    if vault.opened_hash != before || vault.db.is_none() {
        return Ok(false);
    }

    let (changed, ours_ahead) = merge(vault.database_mut()?, &theirs)?;

    if ours_ahead && !vault.read_only {
        write_back(app, &mut vault, &ziel)?;
    } else {
        vault.opened_hash = Some(hash);
        vault.seen_modified = modified;
        vault.offline = false;
        crate::offline::store(app, &ziel, &current);
    }
    Ok(changed)
}

/// Mischt `theirs` in `ours`: Einträge und Ordner werden über ihre UUID
/// einander zugeordnet, von zwei Fassungen gilt die jüngere, die ältere
/// landet im Verlauf; Löschvermerke werden beachtet. Das ist derselbe
/// Abgleich, den KeePassXC beim Zusammenführen macht.
///
/// Zurück kommt (hat sich `ours` geändert, fehlt `theirs` etwas von `ours`).
pub(crate) fn merge(ours: &mut Database, theirs: &Database) -> Result<(bool, bool), String> {
    let log = ours.merge(theirs).map_err(merge_error)?;

    // Umgekehrt noch einmal auf einer Kopie: Kommt dabei nichts heraus,
    // steht in der Datei schon alles, und sie muss nicht neu geschrieben werden.
    let mut probe = theirs.clone();
    let back = probe.merge(ours).map_err(merge_error)?;

    Ok((!log.events.is_empty(), !back.events.is_empty()))
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
fn write_back(app: &tauri::AppHandle, vault: &mut crate::state::VaultState, ziel: &str) -> Result<(), String> {
    let master = vault.master.as_ref().ok_or("Kein Master-Passwort im Kern.")?;
    let key = key_of(master, vault.keyfile.as_deref().map(|k| k.as_slice()))?;

    let mut bytes: Vec<u8> = Vec::new();
    vault
        .database()?
        .save(&mut bytes, key)
        .map_err(|e| format!("Verschlüsseln fehlgeschlagen: {e}"))?;

    crate::storage::write(ziel, &bytes)?;

    // Ab jetzt ist unser eigener Stand der maßgebliche.
    vault.opened_hash = Some(digest(&bytes));
    vault.seen_modified = crate::storage::modified_ms(ziel);
    vault.offline = false;
    crate::offline::store(app, ziel, &bytes);
    Ok(())
}

#[tauri::command]
pub fn vault_lock(state: tauri::State<'_, Vault>) -> Result<bool, String> {
    state.lock().map_err(|_| "Kern blockiert.".to_string())?.clear();
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
}
