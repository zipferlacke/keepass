//! Legt eine Test-Datenbank an — zum Ausprobieren, nie für echte Daten.
//!
//!     cargo run --example testdatenbank -- /tmp/test.kdbx 1234
//!     cargo run --example testdatenbank -- --beispiel /tmp/beispiel.kdbx 1234
//!
//! Ohne `--beispiel` eine kleine mit vier Einträgen. Mit `--beispiel` die
//! größere aus den Demodaten (`src-ui/config/demo.json`): Ordner, Tags,
//! TOTP, Ablaufdaten, Anhänge und ein Papierkorb — dieselben Einträge, die
//! die Weboberfläche im Demo-Modus zeigt, nur als echte KDBX-Datei.
//!
//! Gedacht fürs Handy: Die Datei wandert danach mit `adb push` nach
//! `/sdcard/Download/`, und die App öffnet sie über die Dateiauswahl.

use base64::Engine;
use keepass::db::{fields, GroupId, Value};
use keepass::{Database, DatabaseKey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let beispiel = args.first().is_some_and(|a| a == "--beispiel");
    if beispiel {
        args.remove(0);
    }
    let mut args = args.into_iter();
    let path = args.next().unwrap_or_else(|| "test.kdbx".into());
    let password = args.next().unwrap_or_else(|| "1234".into());

    let mut db = if beispiel { gross()? } else { klein() };

    // Die Stufe „Standard" der App (database.rs) — sonst gälte die Vorgabe
    // der Bibliothek (50 Durchgänge, 1 MiB), und die App zeigte eine
    // „eigene Einstellung", die sich so nicht wieder einstellen lässt.
    db.config.kdf_config = keepass::config::KdfConfig::Argon2id {
        iterations: 10,
        memory: 64 * 1024 * 1024,
        parallelism: 4,
        version: Default::default(),
    };

    let mut bytes = Vec::new();
    db.save(&mut bytes, DatabaseKey::new().with_password(&password))?;
    std::fs::write(&path, &bytes)?;

    println!("{path} angelegt, Passwort: {password}");
    Ok(())
}

fn klein() -> Database {
    let mut db = Database::new();
    db.meta.database_name = Some("Testdatenbank".into());

    let root = db.root().id();
    let ordner = {
        let mut gruppe = db.group_mut(root).unwrap();
        let mut privat = gruppe.add_group();
        privat.name = "Privat".into();
        privat.id()
    };

    for (gruppe, name, benutzer, passwort) in [
        (root, "Nextcloud", "florian", "geheim-1"),
        (root, "GitHub", "zipferlacke", "geheim-2"),
        (ordner, "Stromanbieter", "kunde@example.org", "geheim-3"),
    ] {
        let id = db.group_mut(gruppe).unwrap().add_entry().id();
        let mut eintrag = db.entry_mut(id).unwrap();
        eintrag.set_unprotected(fields::TITLE, name.to_string());
        eintrag.set_unprotected(fields::USERNAME, benutzer.to_string());
        eintrag.set_protected(fields::PASSWORD, passwort.to_string());
    }

    // Ein Anhang, um die Dateiablage auf dem Handy zu prüfen.
    let id = db.root_mut().add_entry().id();
    let mut notiz = db.entry_mut(id).unwrap();
    notiz.set_unprotected(fields::TITLE, "Notizen".to_string());
    notiz.add_attachment(
        "hinweis.md",
        Value::Unprotected(b"# Testdatenbank\n\nNur zum Ausprobieren.\n".to_vec()),
    );
    db
}

/// Die Demodaten der Weboberfläche als KDBX.
fn gross() -> Result<Database, Box<dyn std::error::Error>> {
    let quelle = concat!(env!("CARGO_MANIFEST_DIR"), "/../src-ui/config/demo.json");
    let demo: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(quelle)?)?;
    let text = |v: &serde_json::Value, k: &str| v[k].as_str().unwrap_or_default().to_string();

    let mut db = Database::new();
    db.meta.database_name = Some("Beispieldatenbank".into());

    // Der Ordner „Papierkorb" wird zum Papierkorb der Datei.
    for ordner in demo["folders"].as_array().into_iter().flatten() {
        gruppe(&mut db, ordner.as_str().unwrap_or_default());
    }
    if let Some(bin) = gruppe_finden(&db, "Papierkorb") {
        db.meta.recyclebin_uuid = Some(bin.uuid());
        db.meta.recyclebin_enabled = Some(true);
    }

    let geheim = |token: &serde_json::Value| demo["secrets"][token.as_str().unwrap_or_default()].as_str().map(str::to_string);
    let jetzt = keepass::db::Times::now();

    for e in demo["entries"].as_array().into_iter().flatten() {
        let ziel = gruppe(&mut db, &text(e, "folder"));
        let id = db.group_mut(ziel).unwrap().add_entry().id();
        let mut eintrag = db.entry_mut(id).unwrap();

        eintrag.set_unprotected(fields::TITLE, text(e, "name"));
        eintrag.set_unprotected(fields::USERNAME, text(e, "username"));
        eintrag.set_unprotected(fields::URL, text(e, "url"));
        eintrag.set_unprotected(fields::NOTES, text(e, "notes"));
        if let Some(pw) = geheim(&e["passwordToken"]) {
            eintrag.set_protected(fields::PASSWORD, pw);
        }
        if let Some(secret) = geheim(&e["totpToken"]) {
            let c = &e["totpConfig"];
            let otp = format!(
                "otpauth://totp/{}?secret={secret}&digits={}&period={}&algorithm={}",
                text(e, "name").replace(' ', "%20"),
                c["digits"].as_u64().unwrap_or(6),
                c["period"].as_u64().unwrap_or(30),
                c["algorithm"].as_str().unwrap_or("SHA1"),
            );
            eintrag.set_protected(fields::OTP, otp);
        }
        eintrag.tags = e["tags"].as_array().into_iter().flatten()
            .filter_map(|t| t.as_str().map(str::to_string)).collect();

        let datum = |k: &str| chrono::DateTime::parse_from_rfc3339(e[k].as_str()?).ok().map(|d| d.naive_utc());
        eintrag.times.last_modification = datum("modified").or(Some(jetzt));
        eintrag.times.last_access = datum("accessed");
        if let Some(ablauf) = e["expires"].as_str()
            .and_then(|d| chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").ok())
        {
            eintrag.times.expires = Some(true);
            eintrag.times.expiry = ablauf.and_hms_opt(23, 59, 59);
        }
        // Ein Eintrag im Papierkorb liegt seit zehn Tagen dort — dann
        // zeigt die Liste „Endgültig weg in 20 Tagen".
        eintrag.times.location_changed = Some(jetzt - chrono::Duration::days(10));

        for anhang in e["attachments"].as_array().into_iter().flatten() {
            let Some(daten) = demo["attachments"][anhang["ref"].as_str().unwrap_or_default()]["data"].as_str() else { continue };
            let roh = daten.split_once(',').map(|(_, b)| b).unwrap_or(daten);
            let bytes = base64::engine::general_purpose::STANDARD.decode(roh)?;
            eintrag.add_attachment(&text(anhang, "name"), Value::Unprotected(bytes));
        }
    }
    Ok(db)
}

/// Sucht oder baut die Gruppe zum Pfad („Privat/Gesundheit"). „Allgemein"
/// ist die Wurzel — so heißt sie in der App.
fn gruppe(db: &mut Database, pfad: &str) -> GroupId {
    let mut aktuell = db.root().id();
    for teil in pfad.split('/').map(str::trim).filter(|t| !t.is_empty() && *t != "Allgemein") {
        let vorhanden = db.group(aktuell).unwrap().groups().find(|g| g.name == teil).map(|g| g.id());
        aktuell = match vorhanden {
            Some(id) => id,
            None => {
                let id = db.group_mut(aktuell).unwrap().add_group().id();
                db.group_mut(id).unwrap().name = teil.to_string();
                id
            }
        };
    }
    aktuell
}

fn gruppe_finden(db: &Database, name: &str) -> Option<GroupId> {
    db.root().groups().find(|g| g.name == name).map(|g| g.id())
}
