//! Legt eine kleine Test-Datenbank an — zum Ausprobieren, nie für echte Daten.
//!
//!     cargo run --example testdatenbank -- /tmp/test.kdbx 1234
//!
//! Gedacht fürs Handy: Die Datei wandert danach mit `adb push` nach
//! `/sdcard/Download/`, und die App öffnet sie über die Dateiauswahl.

use keepass::db::{fields, Value};
use keepass::{Database, DatabaseKey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let path = args.next().unwrap_or_else(|| "test.kdbx".into());
    let password = args.next().unwrap_or_else(|| "1234".into());

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

    let mut bytes = Vec::new();
    db.save(&mut bytes, DatabaseKey::new().with_password(&password))?;
    std::fs::write(&path, &bytes)?;

    println!("{path} angelegt, Passwort: {password}");
    Ok(())
}
