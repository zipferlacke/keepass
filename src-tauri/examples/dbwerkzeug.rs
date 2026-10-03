//! Liest und ändert eine Test-Datenbank von außen — so, wie es ein anderes
//! Gerät täte. Für Abgleich-Tests von Hand, nie für echte Daten.
//!
//!     cargo run --example dbwerkzeug -- DATEI PASSWORT ls
//!     cargo run --example dbwerkzeug -- DATEI PASSWORT neu  TITEL [ORDNER]
//!     cargo run --example dbwerkzeug -- DATEI PASSWORT setze TITEL FELD WERT
//!     cargo run --example dbwerkzeug -- DATEI PASSWORT weg  TITEL
//!
//! FELD ist Title, UserName, Password, URL oder Notes. `weg` löscht mit
//! Löschvermerk, wie es KeePassXC beim endgültigen Löschen tut.

use keepass::db::{fields, Times};
use keepass::{Database, DatabaseKey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [datei, passwort, befehl, rest @ ..] = args.as_slice() else {
        eprintln!("Aufruf: DATEI PASSWORT ls|neu|setze|weg …");
        std::process::exit(2);
    };
    let key = || DatabaseKey::new().with_password(passwort);
    let mut db = Database::open(&mut std::fs::File::open(datei)?, key())?;

    let finde = |db: &Database, titel: &str| {
        db.iter_all_entries().find(|e| e.get_title() == Some(titel)).map(|e| e.id())
    };

    match (befehl.as_str(), rest) {
        ("ls", _) => {
            for e in db.iter_all_entries() {
                let ordner = pfad(&db, e.parent().id());
                println!(
                    "{:<28} {:<22} {:<24} geändert {}",
                    e.get_title().unwrap_or_default(),
                    ordner,
                    e.get_username().unwrap_or_default(),
                    e.times.last_modification.map(|t| t.to_string()).unwrap_or_default(),
                );
            }
            println!("— {} Einträge, {} Löschvermerke", db.iter_all_entries().count(), db.deleted_objects.len());
            return Ok(());
        }
        ("neu", [titel, ordner @ ..]) => {
            let ziel = ordner
                .first()
                .and_then(|o| db.iter_all_groups().find(|g| g.name == *o).map(|g| g.id()))
                .unwrap_or_else(|| db.root().id());
            let id = db.group_mut(ziel).unwrap().add_entry().id();
            let mut e = db.entry_mut(id).unwrap();
            e.set_unprotected(fields::TITLE, titel.clone());
            e.set_protected(fields::PASSWORD, "von-aussen".to_string());
            e.times.last_modification = Some(Times::now());
        }
        ("setze", [titel, feld, wert]) => {
            let id = finde(&db, titel).ok_or("Kein solcher Eintrag.")?;
            let mut e = db.entry_mut(id).unwrap();
            if feld == fields::PASSWORD {
                e.set_protected(feld, wert.clone());
            } else {
                e.set_unprotected(feld, wert.clone());
            }
            e.times.last_modification = Some(Times::now());
        }
        ("weg", [titel]) => {
            let id = finde(&db, titel).ok_or("Kein solcher Eintrag.")?;
            db.entry_mut(id).unwrap().track_changes().remove();
        }
        _ => {
            eprintln!("Unbekannter Befehl.");
            std::process::exit(2);
        }
    }

    let mut bytes = Vec::new();
    db.save(&mut bytes, key())?;
    std::fs::write(datei, &bytes)?;
    println!("{datei} geschrieben.");
    Ok(())
}

fn pfad(db: &Database, gruppe: keepass::db::GroupId) -> String {
    let mut teile = Vec::new();
    let mut aktuell = Some(gruppe);
    while let Some(id) = aktuell {
        let g = db.group(id).unwrap();
        aktuell = g.parent().map(|p| p.id());
        if aktuell.is_some() {
            teile.push(g.name.clone());
        }
    }
    teile.reverse();
    if teile.is_empty() { "Allgemein".into() } else { teile.join("/") }
}
