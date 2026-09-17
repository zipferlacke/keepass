//! Der ganze Weg einmal durch: anlegen, schreiben, wieder öffnen.
//!
//! Diese Tests gehen an den Tauri-Kommandos vorbei — die brauchen einen
//! laufenden `AppHandle`. Geprüft wird stattdessen genau das, worauf sich
//! der Kern verlässt: dass eine mit `Database::new()` erzeugte Datei sich
//! zurückschreiben und danach wieder einlesen lässt, mit allem darin.

use std::io::Cursor;

use keepass::db::{fields, Times};
use keepass::{Database, DatabaseKey};

const PASSWORT: &str = "ein-langes-master-passwort";

/// Legt eine Datenbank mit Ordnern, Einträgen und geschützten Werten an.
fn beispiel() -> Database {
    let mut db = Database::new();

    let arbeit = {
        let mut root = db.root_mut();
        let mut gruppe = root.add_group();
        gruppe.name = "Arbeit".into();
        gruppe.id()
    };

    {
        let id = {
            let mut gruppe = db.group_mut(arbeit).unwrap();
            gruppe.add_entry().id()
        };

        let mut eintrag = db.entry_mut(id).unwrap();
        eintrag.set_unprotected(fields::TITLE, "Intranet");
        eintrag.set_unprotected(fields::USERNAME, "m.beispiel");
        eintrag.set_unprotected(fields::URL, "intranet.example.com");
        eintrag.set_protected(fields::PASSWORD, "geheim-1");
        eintrag.set_protected(fields::OTP, "JBSWY3DPEHPK3PXP");
        eintrag.tags.push("Arbeit".into());
        eintrag.times.last_modification = Some(Times::now());
    }

    db
}

fn durch_die_datei(db: &Database) -> Database {
    let mut bytes = Vec::new();
    db.save(&mut bytes, DatabaseKey::new().with_password(PASSWORT))
        .expect("schreiben muss gehen");

    Database::open(
        &mut Cursor::new(bytes),
        DatabaseKey::new().with_password(PASSWORT),
    )
    .expect("und wieder lesen auch")
}

#[test]
fn neue_datenbank_ist_kdbx_4_1() {
    // Nur 4.1 lässt sich zurückschreiben — darauf baut vault_create.
    let db = Database::new();
    assert!(
        matches!(db.config.version, keepass::config::DatabaseVersion::KDB4(1)),
        "Voreinstellung ist {:?}",
        db.config.version
    );
}

#[test]
fn eintraege_ueberleben_den_umlauf() {
    let wieder = durch_die_datei(&beispiel());

    let eintrag = wieder.iter_all_entries().next().expect("ein Eintrag");
    assert_eq!(eintrag.get_title(), Some("Intranet"));
    assert_eq!(eintrag.get_username(), Some("m.beispiel"));
    assert_eq!(eintrag.get_url(), Some("intranet.example.com"));
    assert_eq!(eintrag.tags, vec!["Arbeit".to_string()]);
}

#[test]
fn geschuetzte_werte_bleiben_geschuetzt() {
    let wieder = durch_die_datei(&beispiel());
    let eintrag = wieder.iter_all_entries().next().unwrap();

    assert_eq!(eintrag.get_password(), Some("geheim-1"));
    assert_eq!(eintrag.get(fields::OTP), Some("JBSWY3DPEHPK3PXP"));

    // Und sie liegen weiterhin als geschützt vor, nicht im Klartext.
    let feld = eintrag.fields.get(fields::PASSWORD).expect("Passwortfeld");
    assert!(feld.is_protected(), "Passwort muss geschützt bleiben");
}

#[test]
fn ordner_ueberleben_den_umlauf() {
    let wieder = durch_die_datei(&beispiel());

    let namen: Vec<String> = wieder
        .iter_all_groups()
        .map(|g| g.name.clone())
        .filter(|n| !n.is_empty())
        .collect();

    assert!(namen.contains(&"Arbeit".to_string()), "gefunden: {namen:?}");
}

#[test]
fn falsches_passwort_wird_abgewiesen() {
    let mut bytes = Vec::new();
    beispiel()
        .save(&mut bytes, DatabaseKey::new().with_password(PASSWORT))
        .unwrap();

    let ergebnis = Database::open(
        &mut Cursor::new(bytes),
        DatabaseKey::new().with_password("falsch"),
    );

    assert!(matches!(
        ergebnis,
        Err(keepass::error::DatabaseOpenError::Key(_))
    ));
}

#[test]
fn papierkorb_ueberlebt_den_umlauf() {
    let mut db = beispiel();

    // So legt state::ensure_recycle_bin ihn an.
    let bin = {
        let mut root = db.root_mut();
        let mut gruppe = root.add_group();
        gruppe.name = "Papierkorb".into();
        gruppe.id()
    };
    db.meta.recyclebin_uuid = Some(bin.uuid());
    db.meta.recyclebin_enabled = Some(true);

    let wieder = durch_die_datei(&db);

    assert_eq!(
        wieder.recycle_bin().map(|g| g.name.clone()),
        Some("Papierkorb".to_string()),
        "der Papierkorb muss als solcher wiedererkannt werden"
    );
}

/// Die Verknüpfung eines Browsers steht in `meta.custom_data`.
///
/// Genau da hakte es lange: `associate` schrieb sie nur in den
/// Arbeitsspeicher, nichts gab sie an die Datei weiter, und beim nächsten
/// Start galt der Browser wieder als unbekannt. Seitdem schreibt die
/// Anbindung selbst zurück — was voraussetzt, dass dieses Feld den Umlauf
/// überhaupt übersteht.
#[test]
fn browser_verknuepfung_ueberlebt_den_umlauf() {
    let mut db = beispiel();

    db.meta.custom_data.insert(
        "KPXC_BROWSER_WKeePass ab12cd34".into(),
        keepass::db::CustomDataItem {
            value: Some(keepass::db::CustomDataValue::String("der-schluessel".into())),
            last_modification_time: None,
        },
    );

    let wieder = durch_die_datei(&db);

    let abgelegt = wieder
        .meta
        .custom_data
        .get("KPXC_BROWSER_WKeePass ab12cd34")
        .and_then(|item| item.value.as_ref());

    assert!(
        matches!(abgelegt, Some(keepass::db::CustomDataValue::String(text)) if text == "der-schluessel"),
        "der Verknüpfungsschlüssel muss in der Datei landen, sonst fragt der Browser jedes Mal neu"
    );
}
