//! Die letzten Stände jeder Datenbank — das Netz unter dem Abgleich.
//!
//! # Wozu
//!
//! Die Datei liegt in einem Ordner, den zwei Geräte beschreiben. Beim
//! Zusammenführen kann etwas schiefgehen: ein Eintrag, der plötzlich fehlt,
//! ein Passwort, das die ältere Fassung überschrieben hat. Ohne Netz wäre
//! das endgültig — die Datei ist ja nur eine.
//!
//! Deshalb hebt der Kern [`WIE_VIELE`] Stände auf: bei jedem Öffnen, nach
//! jedem Speichern und immer dann, wenn ein anderes Gerät die Datei
//! geändert hat. Jeder Stand ist die vollständige Datei, **verschlüsselt
//! wie das Original** — Klartext liegt hier nie.
//!
//! # Was man damit tut
//!
//! [`vergleich`] sagt, was sich seit einem Stand geändert hat: welche
//! Einträge dazugekommen, verschwunden oder anders sind. Zurückholen kann
//! man alles ([`alles_zurueck`]) oder einzelne Einträge
//! ([`eintrag_zurueck`]) — der Rest bleibt, wie er ist.
//!
//! Passwörter stehen dabei **nie** im Vergleich: Dass sich eins geändert
//! hat, genügt der Oberfläche. Sonst läge der Klartext zweier Fassungen im
//! Webview, nur um einen Unterschied anzuzeigen.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use keepass::db::{Database, EntryRef};
use tauri::Manager;

use crate::dto;

/// So viele Stände je Datenbank. Mehr hilft nicht — wer weiter zurück will,
/// sucht ohnehin in der Sicherung des Rechners.
pub const WIE_VIELE: usize = 20;

/// Warum ein Stand abgelegt wurde. Steht im Dateinamen und in der Liste.
#[derive(Clone, Copy, PartialEq)]
pub enum Grund {
    /// Beim Entsperren — so lag die Datei da.
    Geoeffnet,
    /// Nach dem Zurückschreiben.
    Gespeichert,
    /// Ein anderes Gerät hat die Datei geändert.
    Fremd,
}

impl Grund {
    fn kennung(self) -> &'static str {
        match self {
            Grund::Geoeffnet => "geoeffnet",
            Grund::Gespeichert => "gespeichert",
            Grund::Fremd => "fremd",
        }
    }

    fn text(kennung: &str) -> &'static str {
        match kennung {
            "gespeichert" => "Gespeichert",
            "fremd" => "Vom anderen Gerät",
            _ => "Beim Öffnen",
        }
    }
}

/* =========================================================
   Ablage
   ========================================================= */

/// `<Datenverzeichnis>/versionen/<SHA-256 des Pfads>/`
///
/// Gehasht wie bei der Offline-Kopie: Der Pfad selbst taugt nicht als
/// Dateiname, und zwei gleichnamige Dateien aus verschiedenen Ordnern
/// dürfen sich nicht in die Quere kommen.
fn ordner(app: &tauri::AppHandle, pfad: &str) -> Option<PathBuf> {
    use sha2::{Digest, Sha256};

    let hash = Sha256::digest(pfad.as_bytes());
    let name: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    Some(app.path().app_local_data_dir().ok()?.join("versionen").join(name))
}

/// Ein Abdruck dessen, was in der Datenbank steht — ohne alles, was sich
/// beim bloßen Speichern ändert.
///
/// Zwei Dateien mit demselben Inhalt sind Byte für Byte verschieden: Jedes
/// Speichern würfelt Salz und Startwert neu. Wer wissen will, ob sich
/// **etwas** geändert hat, muss deshalb den Inhalt vergleichen. Hinein
/// gehen je Eintrag Kennung, Ordner, alle Felder, Schlagworte und die
/// Anhänge; heraus bleiben Zeitstempel und Verlauf.
///
/// Der Abdruck bleibt im Arbeitsspeicher und verlässt den Kern nie.
pub fn abdruck(db: &Database) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    // Je Eintrag ein eigener Abdruck, dann sortiert zusammen — die
    // Reihenfolge, in der die Bibliothek die Einträge liefert, soll nichts
    // ausmachen.
    let mut einzeln: Vec<[u8; 32]> = db
        .iter_all_entries()
        .map(|e| {
            let mut h = Sha256::new();
            let teil = |h: &mut Sha256, text: &str| {
                h.update((text.len() as u64).to_le_bytes());
                h.update(text.as_bytes());
            };

            teil(&mut h, &e.id().uuid().to_string());
            teil(&mut h, &ordnerpfad(db, &e));

            let mut schluessel: Vec<&String> = e.fields.keys().collect();
            schluessel.sort();
            for k in schluessel {
                teil(&mut h, k);
                teil(&mut h, e.get(k).unwrap_or_default());
            }

            let mut tags: Vec<&String> = e.tags.iter().collect();
            tags.sort();
            for t in tags {
                teil(&mut h, t);
            }

            let mut anhaenge: Vec<[u8; 32]> =
                e.attachments().map(|a| Sha256::digest(a.data.get()).into()).collect();
            anhaenge.sort();
            for a in anhaenge {
                h.update(a);
            }

            h.finalize().into()
        })
        .collect();
    einzeln.sort();

    let mut gesamt = Sha256::new();
    for e in einzeln {
        gesamt.update(e);
    }
    gesamt.finalize().into()
}

/// Der Abdruck des zuletzt abgelegten Stands, je Datenbank.
fn letzter_abdruck() -> &'static std::sync::Mutex<HashMap<String, [u8; 32]>> {
    static LETZTER: std::sync::OnceLock<std::sync::Mutex<HashMap<String, [u8; 32]>>> =
        std::sync::OnceLock::new();
    LETZTER.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

/// Lohnt ein neuer Stand? Nur, wenn sich am Inhalt etwas getan hat.
fn lohnt(letzter: Option<&[u8; 32]>, neu: &[u8; 32]) -> bool {
    letzter != Some(neu)
}

/// Legt einen Stand ab — aber nur, wenn er sich vom letzten unterscheidet.
///
/// Ein Stand ohne Unterschied ist kein Stand: Er verdrängt einen echten aus
/// den [`WIE_VIELE`], und in der Liste steht dann „nichts geändert". Das
/// passiert leicht — Speichern ohne Änderung, Öffnen direkt nach dem
/// Speichern, eine andere Verschlüsselungsstärke.
///
/// `abdruck` ist der Abdruck des Inhalts (siehe [`abdruck`]). Fehler werden
/// nur gemeldet: Ohne Netz geht alles weiter wie bisher, nur eben ohne Netz.
pub fn sichern(app: &tauri::AppHandle, pfad: &str, bytes: &[u8], grund: Grund, abdruck: [u8; 32]) {
    let Some(dir) = ordner(app, pfad) else { return };
    let Ok(mut letzter) = letzter_abdruck().lock() else { return };

    // Byte für Byte dieselbe Datei wie der jüngste Stand — etwa Öffnen
    // direkt nach dem Speichern. Das fängt auch den Fall nach einem
    // Neustart, in dem noch kein Abdruck im Speicher steht.
    let gleiche_datei = liste_roh(&dir)
        .last()
        .is_some_and(|l| std::fs::read(&l.datei).is_ok_and(|alt| alt == bytes));

    if gleiche_datei || !lohnt(letzter.get(pfad), &abdruck) {
        letzter.insert(pfad.to_string(), abdruck);
        return;
    }

    match schreiben(&dir, bytes, grund) {
        Ok(()) => {
            letzter.insert(pfad.to_string(), abdruck);
        }
        Err(err) => eprintln!("[versionen] nicht gesichert: {err}"),
    }
    aufraeumen(&dir);
}

fn schreiben(dir: &std::path::Path, bytes: &[u8], grund: Grund) -> Result<(), String> {
    use std::io::Write;

    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let ms = chrono::Local::now().timestamp_millis();
    let ziel = dir.join(format!("{ms}-{}.kdbx", grund.kennung()));

    // Erst daneben, dann umbenennen: ein halber Stand wäre schlimmer als
    // keiner.
    let tmp = ziel.with_extension("kdbx.tmp");
    {
        let mut datei = std::fs::File::create(&tmp).map_err(|e| e.to_string())?;
        datei.write_all(bytes).map_err(|e| e.to_string())?;
        datei.sync_all().map_err(|e| e.to_string())?;
    }
    std::fs::rename(&tmp, &ziel).map_err(|e| e.to_string())
}

/// Wirft die ältesten Stände weg, bis nur noch [`WIE_VIELE`] da sind.
fn aufraeumen(dir: &std::path::Path) {
    let mut staende = liste_roh(dir);
    while staende.len() > WIE_VIELE {
        let alt = staende.remove(0);
        let _ = std::fs::remove_file(&alt.datei);
    }
}

struct Eintrag {
    datei: PathBuf,
    id: String,
    ms: i64,
    grund: String,
    groesse: u64,
}

/// Alle Stände, älteste zuerst.
fn liste_roh(dir: &std::path::Path) -> Vec<Eintrag> {
    let Ok(lesen) = std::fs::read_dir(dir) else { return Vec::new() };

    let mut out: Vec<Eintrag> = lesen
        .flatten()
        .filter_map(|e| {
            let datei = e.path();
            let name = datei.file_stem()?.to_str()?.to_string();
            if datei.extension()? != "kdbx" {
                return None;
            }
            let (ms, grund) = name.split_once('-')?;
            Some(Eintrag {
                groesse: e.metadata().ok()?.len(),
                ms: ms.parse().ok()?,
                grund: grund.to_string(),
                id: name,
                datei,
            })
        })
        .collect();

    out.sort_by_key(|e| e.ms);
    out
}

/// Die Stände für die Oberfläche — der jüngste zuerst.
///
/// Der Stand, der gerade offen ist, trägt `current`: `ist_aktuell` erkennt
/// ihn an den Bytes der Datei. Auch er sagt, was er geändert hat — nur
/// zurück auf ihn gibt es nichts.
pub fn liste(app: &tauri::AppHandle, pfad: &str, ist_aktuell: impl Fn(&[u8]) -> bool) -> Vec<dto::Version> {
    let Some(dir) = ordner(app, pfad) else { return Vec::new() };

    let mut out: Vec<dto::Version> = liste_roh(&dir)
        .into_iter()
        .map(|e| dto::Version {
            current: std::fs::read(&e.datei).is_ok_and(|bytes| ist_aktuell(&bytes)),
            id: e.id,
            at: chrono::DateTime::from_timestamp_millis(e.ms)
                .map(|t| t.with_timezone(&chrono::Local).to_rfc3339())
                .unwrap_or_default(),
            reason: Grund::text(&e.grund).to_string(),
            size: e.groesse,
        })
        .collect();
    out.reverse();
    out
}

/// Der Stand unmittelbar vor `id` — `None`, wenn `id` der älteste ist.
pub fn vorgaenger(app: &tauri::AppHandle, pfad: &str, id: &str) -> Option<String> {
    let dir = ordner(app, pfad)?;
    let staende = liste_roh(&dir);
    let i = staende.iter().position(|e| e.id == id)?;
    i.checked_sub(1).map(|j| staende[j].id.clone())
}

/// Die Bytes eines Stands.
pub fn lesen(app: &tauri::AppHandle, pfad: &str, id: &str) -> Result<Vec<u8>, String> {
    // Keine Schrägstriche, keine Punkte: `id` kommt aus der Oberfläche, und
    // ein Name wie `../../woanders` hätte hier nichts zu suchen.
    if !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err("Unbekannter Stand.".into());
    }
    let dir = ordner(app, pfad).ok_or("Kein Datenverzeichnis.")?;
    std::fs::read(dir.join(format!("{id}.kdbx")))
        .map_err(|e| format!("Der Stand ist nicht mehr lesbar: {e}"))
}

/* =========================================================
   Vergleich
   ========================================================= */

/// Welche Felder verglichen werden — Name für die Oberfläche, Schlüssel im
/// Eintrag. Das Passwort steht bewusst nicht dabei (siehe oben).
const FELDER: [(&str, &str); 4] = [
    ("Titel", "Title"),
    ("Benutzername", "UserName"),
    ("Adresse", "URL"),
    ("Notizen", "Notes"),
];

fn wert(entry: &EntryRef<'_>, schluessel: &str) -> String {
    entry.get(schluessel).unwrap_or_default().to_string()
}

fn ordnerpfad(db: &Database, entry: &EntryRef<'_>) -> String {
    crate::state::folder_path(db, entry.parent().id())
}

/// Was sich seit `alt` geändert hat — aus Sicht des jetzigen Stands.
pub fn vergleich(alt: &Database, jetzt: &Database) -> Vec<dto::VersionChange> {
    let mut frueher: HashMap<String, EntryRef<'_>> = HashMap::new();
    for e in alt.iter_all_entries() {
        frueher.insert(e.id().uuid().to_string(), e);
    }

    let mut out = Vec::new();
    let mut gesehen: HashSet<String> = HashSet::new();

    for heute in jetzt.iter_all_entries() {
        let uuid = heute.id().uuid().to_string();
        gesehen.insert(uuid.clone());

        let Some(damals) = frueher.get(&uuid) else {
            out.push(dto::VersionChange {
                id: uuid,
                name: heute.get_title().unwrap_or_default().to_string(),
                folder: ordnerpfad(jetzt, &heute),
                kind: "neu".into(),
                fields: Vec::new(),
            });
            continue;
        };

        let mut felder: Vec<dto::VersionField> = FELDER
            .iter()
            .filter_map(|(name, schluessel)| {
                let vorher = wert(damals, schluessel);
                let nachher = wert(&heute, schluessel);
                (vorher != nachher).then(|| dto::VersionField {
                    name: (*name).to_string(),
                    before: Some(vorher),
                    after: Some(nachher),
                })
            })
            .collect();

        // Geheimnisse ohne Werte: dass sie anders sind, reicht.
        for (name, vorher, nachher) in [
            ("Passwort", damals.get_password(), heute.get_password()),
            ("Einmalcode", damals.get_raw_otp_value(), heute.get_raw_otp_value()),
        ] {
            if vorher.unwrap_or_default() != nachher.unwrap_or_default() {
                felder.push(dto::VersionField { name: name.to_string(), before: None, after: None });
            }
        }

        let vorher_ordner = ordnerpfad(alt, damals);
        let jetzt_ordner = ordnerpfad(jetzt, &heute);
        if vorher_ordner != jetzt_ordner {
            felder.push(dto::VersionField {
                name: "Ordner".into(),
                before: Some(vorher_ordner),
                after: Some(jetzt_ordner.clone()),
            });
        }

        let anhaenge_vorher = damals.attachments().count();
        let anhaenge_jetzt = heute.attachments().count();
        if anhaenge_vorher != anhaenge_jetzt {
            felder.push(dto::VersionField {
                name: "Anhänge".into(),
                before: Some(anhaenge_vorher.to_string()),
                after: Some(anhaenge_jetzt.to_string()),
            });
        }

        if !felder.is_empty() {
            out.push(dto::VersionChange {
                id: uuid,
                name: heute.get_title().unwrap_or_default().to_string(),
                folder: jetzt_ordner,
                kind: "geaendert".into(),
                fields: felder,
            });
        }
    }

    // Was es damals gab und heute nicht mehr.
    for (uuid, damals) in &frueher {
        if gesehen.contains(uuid) {
            continue;
        }
        out.push(dto::VersionChange {
            id: uuid.clone(),
            name: damals.get_title().unwrap_or_default().to_string(),
            folder: ordnerpfad(alt, damals),
            kind: "geloescht".into(),
            fields: Vec::new(),
        });
    }

    out.sort_by_key(|c| c.name.to_lowercase());
    out
}

/* =========================================================
   Zurückholen
   ========================================================= */

/// Holt einen einzelnen Eintrag in den Stand von damals zurück.
///
/// Gab es ihn damals nicht, ist das Zurücknehmen seine Entfernung — er ist
/// ja erst nach diesem Stand entstanden.
pub fn eintrag_zurueck(jetzt: &mut Database, alt: &Database, uuid: &str) -> Result<(), String> {
    let damals = alt.iter_all_entries().find(|e| e.id().uuid().to_string() == uuid);
    let heute = jetzt.iter_all_entries().find(|e| e.id().uuid().to_string() == uuid).map(|e| e.id());

    let Some(damals) = damals else {
        // Nach diesem Stand entstanden: zurücknehmen heißt entfernen — mit
        // Löschvermerk, sonst brächte ihn der Abgleich zurück.
        let id = heute.ok_or("Der Eintrag ist nicht mehr da.")?;
        jetzt.entry_mut(id).ok_or("Der Eintrag ist nicht mehr da.")?.track_changes().remove();
        return Ok(());
    };

    let ordner = ordnerpfad(alt, &damals);
    let ziel = crate::state::ensure_group(jetzt, &ordner);

    // War er endgültig gelöscht, steht noch ein Löschvermerk in der Datei.
    // Der muss weg — sonst nähme ihn ein anderes Gerät beim Abgleich als
    // Auftrag, den Eintrag wieder zu entfernen.
    jetzt.deleted_objects.remove(&damals.id().uuid());

    // Vorhandenen Eintrag überschreiben, verschwundenen neu anlegen — mit
    // derselben Kennung, damit der Abgleich ihn weiterhin wiedererkennt.
    let id = match heute {
        Some(id) => id,
        None => jetzt
            .group_mut(ziel)
            .ok_or("Zielordner verschwunden.")?
            .add_entry_with_id(damals.id())
            .map_err(|_| "Diese Kennung gibt es schon.".to_string())?
            .id(),
    };

    let felder = damals.fields.clone();
    let tags = damals.tags.clone();

    // Den heutigen Ordner ablesen, solange die Datenbank noch unveränderlich
    // ausgeliehen ist — `EntryMut` gibt ihn nicht her.
    let heutiger_ordner = jetzt.entry(id).map(|e| e.parent().id());

    let mut eintrag = jetzt.entry_mut(id).ok_or("Der Eintrag ist nicht mehr da.")?;
    if heutiger_ordner != Some(ziel) {
        eintrag
            .move_to(ziel)
            .map_err(|e| format!("Verschieben fehlgeschlagen: {e}"))?;
    }
    let mut eintrag = eintrag.track_changes();
    eintrag.fields = felder;
    eintrag.tags = tags;
    eintrag.times.last_modification = Some(keepass::db::Times::now());
    Ok(())
}

/// Nimmt alles zurück: Jeder Eintrag, der sich geändert hat, bekommt wieder
/// den Stand von damals.
pub fn alles_zurueck(jetzt: &mut Database, alt: &Database) -> Result<usize, String> {
    let betroffen: Vec<String> = vergleich(alt, jetzt).into_iter().map(|c| c.id).collect();
    for uuid in &betroffen {
        eintrag_zurueck(jetzt, alt, uuid)?;
    }
    Ok(betroffen.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ensure_group;

    /// Legt einen Eintrag an und gibt seine Kennung als Text zurück.
    fn eintrag(db: &mut Database, ordner: &str, titel: &str, passwort: &str) -> String {
        let gruppe = ensure_group(db, ordner);
        #[allow(clippy::expect_used)]
        let mut group = db.group_mut(gruppe).expect("Gruppe existiert");
        let mut neu = group.add_entry();
        neu.set_unprotected("Title", titel);
        neu.set_protected("Password", passwort);
        neu.id().uuid().to_string()
    }

    fn setzen(db: &mut Database, uuid: &str, schluessel: &str, wert: &str) {
        #[allow(clippy::expect_used)]
        let id = db
            .iter_all_entries()
            .find(|e| e.id().uuid().to_string() == uuid)
            .expect("Eintrag existiert")
            .id();
        #[allow(clippy::expect_used)]
        let mut e = db.entry_mut(id).expect("Eintrag existiert");
        e.set_unprotected(schluessel.to_string(), wert);
    }

    fn titel(db: &Database, uuid: &str) -> Option<String> {
        db.iter_all_entries()
            .find(|e| e.id().uuid().to_string() == uuid)
            .map(|e| e.get_title().unwrap_or_default().to_string())
    }

    #[test]
    fn vergleich_nennt_neu_geloescht_und_geaendert() {
        let mut alt = Database::new();
        let bank = eintrag(&mut alt, "Allgemein", "Bank", "geheim");
        let weg = eintrag(&mut alt, "Allgemein", "Altes Konto", "egal");

        let mut jetzt = alt.clone();
        setzen(&mut jetzt, &bank, "UserName", "max");
        let neu = eintrag(&mut jetzt, "Allgemein", "Neuer Dienst", "frisch");
        #[allow(clippy::expect_used)]
        let weg_id = jetzt
            .iter_all_entries()
            .find(|e| e.id().uuid().to_string() == weg)
            .expect("Eintrag existiert")
            .id();
        #[allow(clippy::expect_used)]
        jetzt.entry_mut(weg_id).expect("Eintrag existiert").remove();

        let changes = vergleich(&alt, &jetzt);
        let art = |uuid: &str| {
            changes.iter().find(|c| c.id == uuid).map(|c| c.kind.clone())
        };

        assert_eq!(art(&bank).as_deref(), Some("geaendert"));
        assert_eq!(art(&neu).as_deref(), Some("neu"));
        assert_eq!(art(&weg).as_deref(), Some("geloescht"));

        // Der Benutzername steht mit beiden Werten da …
        #[allow(clippy::expect_used)]
        let geaendert = changes.iter().find(|c| c.id == bank).expect("Eintrag dabei");
        #[allow(clippy::expect_used)]
        let feld = geaendert.fields.iter().find(|f| f.name == "Benutzername").expect("Feld dabei");
        assert_eq!(feld.after.as_deref(), Some("max"));
    }

    /// Geheimnisse gehören nicht in den Vergleich — nur die Tatsache.
    #[test]
    fn passwort_steht_ohne_werte_da() {
        let mut alt = Database::new();
        let id = eintrag(&mut alt, "Allgemein", "Bank", "altes-geheim");
        let mut jetzt = alt.clone();
        setzen(&mut jetzt, &id, "Password", "neues-geheim");

        let changes = vergleich(&alt, &jetzt);
        #[allow(clippy::expect_used)]
        let feld = changes[0].fields.iter().find(|f| f.name == "Passwort").expect("Feld dabei");
        assert_eq!(feld.before, None);
        assert_eq!(feld.after, None);
    }

    #[test]
    fn einzelner_eintrag_kommt_zurueck() {
        let mut alt = Database::new();
        let bank = eintrag(&mut alt, "Allgemein", "Bank", "geheim");
        let mail = eintrag(&mut alt, "Allgemein", "Mail", "geheim");

        let mut jetzt = alt.clone();
        setzen(&mut jetzt, &bank, "Title", "Bank (kaputt)");
        setzen(&mut jetzt, &mail, "Title", "Mail (neu)");

        #[allow(clippy::expect_used)]
        eintrag_zurueck(&mut jetzt, &alt, &bank).expect("zurückholen klappt");

        assert_eq!(titel(&jetzt, &bank).as_deref(), Some("Bank"));
        // Der andere bleibt, wie er ist — zurück kommt nur das Gewählte.
        assert_eq!(titel(&jetzt, &mail).as_deref(), Some("Mail (neu)"));
    }

    /// Ein Eintrag, den es damals nicht gab: Zurücknehmen heißt entfernen.
    #[test]
    fn spaeter_entstandener_eintrag_verschwindet() {
        let alt = Database::new();
        let mut jetzt = alt.clone();
        let neu = eintrag(&mut jetzt, "Allgemein", "Versehen", "x");

        #[allow(clippy::expect_used)]
        eintrag_zurueck(&mut jetzt, &alt, &neu).expect("zurückholen klappt");
        assert_eq!(titel(&jetzt, &neu), None);
        // Mit Löschvermerk, sonst brächte ihn der Abgleich zurück.
        assert_eq!(jetzt.deleted_objects.len(), 1);
    }

    #[test]
    fn geloeschter_eintrag_kommt_mit_kennung_zurueck() {
        let mut alt = Database::new();
        let bank = eintrag(&mut alt, "Arbeit", "Bank", "geheim");

        let mut jetzt = alt.clone();
        #[allow(clippy::expect_used)]
        let id = jetzt
            .iter_all_entries()
            .find(|e| e.id().uuid().to_string() == bank)
            .expect("Eintrag existiert")
            .id();
        #[allow(clippy::expect_used)]
        jetzt.entry_mut(id).expect("Eintrag existiert").track_changes().remove();
        assert_eq!(jetzt.deleted_objects.len(), 1);

        #[allow(clippy::expect_used)]
        eintrag_zurueck(&mut jetzt, &alt, &bank).expect("zurückholen klappt");

        assert_eq!(titel(&jetzt, &bank).as_deref(), Some("Bank"));
        // Der Löschvermerk ist weg — ein anderes Gerät soll ihn nicht
        // wieder entfernen.
        assert!(jetzt.deleted_objects.is_empty());
        // Im selben Ordner wie damals.
        #[allow(clippy::expect_used)]
        let e = jetzt
            .iter_all_entries()
            .find(|e| e.id().uuid().to_string() == bank)
            .expect("Eintrag existiert");
        assert_eq!(crate::state::folder_path(&jetzt, e.parent().id()), "Arbeit");
    }

    #[test]
    fn alles_zurueck_setzt_jede_aenderung_zurueck() {
        let mut alt = Database::new();
        let bank = eintrag(&mut alt, "Allgemein", "Bank", "geheim");
        let mail = eintrag(&mut alt, "Allgemein", "Mail", "geheim");

        let mut jetzt = alt.clone();
        setzen(&mut jetzt, &bank, "Title", "Bank (kaputt)");
        setzen(&mut jetzt, &mail, "UserName", "fremd");
        let versehen = eintrag(&mut jetzt, "Allgemein", "Versehen", "x");

        #[allow(clippy::expect_used)]
        let zahl = alles_zurueck(&mut jetzt, &alt).expect("zurückholen klappt");
        assert_eq!(zahl, 3);
        assert!(vergleich(&alt, &jetzt).is_empty());
        assert_eq!(titel(&jetzt, &versehen), None);
    }

    fn gespeichert_und_gelesen(db: &Database) -> (Vec<u8>, Database) {
        use keepass::DatabaseKey;
        let mut bytes = Vec::new();
        #[allow(clippy::expect_used)]
        db.save(&mut bytes, DatabaseKey::new().with_password("test")).expect("speichern");
        #[allow(clippy::expect_used)]
        let wieder = Database::parse(&bytes[..], DatabaseKey::new().with_password("test")).expect("lesen");
        (bytes, wieder)
    }

    /// Zweimal gespeichert ergibt zwei verschiedene Dateien mit demselben
    /// Inhalt — der Abdruck sieht nur den Inhalt.
    #[test]
    fn abdruck_bleibt_beim_blossen_speichern() {
        let mut db = Database::new();
        eintrag(&mut db, "Bank", "Konto", "geheim");
        eintrag(&mut db, "", "Webmail", "auch geheim");

        let (erste, a) = gespeichert_und_gelesen(&db);
        let (zweite, b) = gespeichert_und_gelesen(&db);

        assert_ne!(erste, zweite, "jedes Speichern würfelt neu");
        assert_eq!(abdruck(&a), abdruck(&b));
        assert_eq!(abdruck(&db), abdruck(&a));
    }

    /// Alles, was man zurückholen könnte, verändert den Abdruck.
    #[test]
    fn abdruck_aendert_sich_mit_dem_inhalt() {
        let mut db = Database::new();
        let uuid = eintrag(&mut db, "Bank", "Konto", "geheim");
        let vorher = abdruck(&db);

        let mut titel_anders = db.clone();
        setzen(&mut titel_anders, &uuid, "Title", "Girokonto");
        assert_ne!(abdruck(&titel_anders), vorher, "Titel");

        let mut passwort_anders = db.clone();
        setzen(&mut passwort_anders, &uuid, "Password", "neu");
        assert_ne!(abdruck(&passwort_anders), vorher, "Passwort");

        let mut eigenes_feld = db.clone();
        setzen(&mut eigenes_feld, &uuid, "Kundennummer", "4711");
        assert_ne!(abdruck(&eigenes_feld), vorher, "eigenes Feld");

        let mut dazu = db.clone();
        eintrag(&mut dazu, "Bank", "Depot", "x");
        assert_ne!(abdruck(&dazu), vorher, "neuer Eintrag");

        let mut anderswo = Database::new();
        eintrag(&mut anderswo, "Privat", "Konto", "geheim");
        assert_ne!(abdruck(&anderswo), vorher, "anderer Ordner, andere Kennung");
    }

    /// Ohne Unterschied kein Stand; beim ersten Mal immer einer.
    #[test]
    fn stand_lohnt_nur_bei_unterschied() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert!(lohnt(None, &a), "noch keiner abgelegt");
        assert!(!lohnt(Some(&a), &a), "derselbe Inhalt");
        assert!(lohnt(Some(&a), &b), "anderer Inhalt");
    }
}
