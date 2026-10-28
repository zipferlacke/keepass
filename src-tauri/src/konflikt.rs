//! Konflikte beim Zusammenführen.
//!
//! Das Zusammenführen (`database::merge`) entscheidet je Eintrag nach der
//! Uhr: Die jüngere Fassung gilt, die ältere landet im Verlauf. Meist ist
//! das richtig — eine Seite hat etwas geändert, die andere nicht.
//!
//! Haben aber **beide** Seiten denselben Eintrag seit dem letzten
//! gemeinsamen Stand geändert, und verschieden, dann entscheidet die Uhr
//! über etwas, das der Nutzer selbst entscheiden sollte: Hier hat er das
//! Passwort geändert, auf dem anderen Gerät die Adresse — welche Fassung
//! soll gelten? Das sind die Konflikte, die hier gefunden werden.
//!
//! # Die gemeinsame Basis
//!
//! Der jüngste aufgehobene Stand (`versions::juengster`): der letzte Stand
//! der Datei, den dieses Gerät gesehen hat — beim Öffnen, Speichern oder
//! Einmischen. Was die App seitdem geändert hat, steht nur in der App; was
//! seitdem in der Datei dazukam, kam von woanders.
//!
//! # Was bis zur Entscheidung gilt
//!
//! Die Fassung, die das Zusammenführen gewählt hat (die jüngere). Die
//! andere hält der Kern bereit, zusammen mit seiner eigenen — wer wählt,
//! bekommt genau die Fassung, die er gesehen hat.

use std::collections::HashMap;
use std::sync::Arc;

use keepass::Database;

use crate::dto;

/// Ein offener Konflikt und die beiden Fassungen, aus denen gewählt wird.
pub struct Offen {
    pub info: dto::Conflict,
    /// Der Stand der App vor dem Zusammenführen.
    pub hier: Arc<Database>,
    /// Der Stand der Datei.
    pub datei: Arc<Database>,
}

/// Findet die Einträge, die beide Seiten seit `basis` verschieden geändert
/// haben. `ergebnis` ist der zusammengeführte Stand — daran zeigt sich,
/// welche Fassung gerade gilt.
pub fn finden(basis: &Database, hier: &Database, datei: &Database, ergebnis: &Database) -> Vec<dto::Conflict> {
    let von_hier: HashMap<String, dto::VersionChange> = crate::versions::vergleich(basis, hier)
        .into_iter()
        .map(|c| (c.id.clone(), c))
        .collect();

    let mut out = Vec::new();
    for aus_datei in crate::versions::vergleich(basis, datei) {
        let Some(eigen) = von_hier.get(&aus_datei.id) else { continue };

        // Neu kann ein Eintrag nur auf einer Seite sein (eigene Kennung);
        // auf beiden Seiten gelöscht ist kein Widerspruch.
        if eigen.kind == "neu" || aus_datei.kind == "neu" {
            continue;
        }
        if eigen.kind == "geloescht" && aus_datei.kind == "geloescht" {
            continue;
        }
        // Beide Seiten haben dasselbe daraus gemacht.
        let fassung_hier = crate::versions::eintrag_abdruck(hier, &eigen.id);
        let fassung_datei = crate::versions::eintrag_abdruck(datei, &eigen.id);
        if fassung_hier == fassung_datei {
            continue;
        }

        let jetzt = crate::versions::eintrag_abdruck(ergebnis, &eigen.id);
        let winner = if jetzt == fassung_hier { "hier" } else { "extern" };

        out.push(dto::Conflict {
            id: eigen.id.clone(),
            name: if eigen.name.is_empty() { aus_datei.name.clone() } else { eigen.name.clone() },
            folder: eigen.folder.clone(),
            here_kind: eigen.kind.clone(),
            here: eigen.fields.clone(),
            file_kind: aus_datei.kind.clone(),
            file: aus_datei.fields.clone(),
            winner: winner.to_string(),
        });
    }
    out.sort_by_key(|c| c.name.to_lowercase());
    out
}

/// Übernimmt neue Konflikte in die offenen. Einer zu demselben Eintrag
/// ersetzt den alten — er ist der jüngere Stand der Dinge.
pub fn merken(offen: &mut Vec<Offen>, neu: Vec<dto::Conflict>, hier: Database, datei: Database) {
    if neu.is_empty() {
        return;
    }
    let (hier, datei) = (Arc::new(hier), Arc::new(datei));
    for info in neu {
        offen.retain(|o| o.info.id != info.id);
        offen.push(Offen { info, hier: hier.clone(), datei: datei.clone() });
    }
}

/// Entscheidet einen Konflikt: Der Eintrag bekommt die gewählte Fassung —
/// `hier` oder `extern`. Hatte die gewählte Seite ihn gelöscht, wird er
/// gelöscht.
pub fn entscheiden(jetzt: &mut Database, offen: &mut Vec<Offen>, id: &str, wahl: &str) -> Result<(), String> {
    let i = offen.iter().position(|o| o.info.id == id).ok_or("Diesen Konflikt gibt es nicht mehr.")?;
    let quelle = match wahl {
        "hier" => offen[i].hier.clone(),
        "extern" => offen[i].datei.clone(),
        other => return Err(format!("Unbekannte Wahl: {other}")),
    };
    crate::versions::eintrag_zurueck(jetzt, &quelle, id)?;
    offen.remove(i);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ensure_group;

    fn eintrag(db: &mut Database, titel: &str) -> String {
        let g = ensure_group(db, "Allgemein");
        let mut gruppe = db.group_mut(g).unwrap();
        let mut e = gruppe.add_entry();
        e.set_unprotected("Title", titel);
        e.id().uuid().to_string()
    }

    /// Ändert ein Feld, `sek` Sekunden nach jetzt — so sind die Seiten
    /// verschieden alt, wie im Leben.
    fn setzen_um(db: &mut Database, uuid: &str, feld: &str, wert: &str, sek: i64) {
        let id = db.iter_all_entries().find(|e| e.id().uuid().to_string() == uuid).unwrap().id();
        let mut e = db.entry_mut(id).unwrap();
        e.set_unprotected(feld.to_string(), wert);
        e.times.last_modification = Some(keepass::db::Times::now() + chrono::Duration::seconds(sek));
    }

    fn setzen(db: &mut Database, uuid: &str, feld: &str, wert: &str) {
        setzen_um(db, uuid, feld, wert, 0);
    }

    fn feld(db: &Database, uuid: &str, feld: &str) -> Option<String> {
        db.iter_all_entries()
            .find(|e| e.id().uuid().to_string() == uuid)
            .map(|e| e.get(feld).unwrap_or_default().to_string())
    }

    /// Beispiel des Nutzers: Extern zwei neue Einträge und einer geändert,
    /// hier ein neuer — kein Konflikt. Erst wenn beide Seiten denselben
    /// Eintrag verschieden ändern, ist es einer.
    #[test]
    fn nur_beidseitig_verschieden_geaendert_ist_ein_konflikt() {
        let mut basis = Database::new();
        let a = eintrag(&mut basis, "A");
        let b = eintrag(&mut basis, "B");

        let mut datei = basis.clone();
        eintrag(&mut datei, "Neu extern 1");
        eintrag(&mut datei, "Neu extern 2");
        setzen_um(&mut datei, &a, "URL", "https://extern", 10);
        setzen_um(&mut datei, &b, "UserName", "gleich", 10);

        let mut hier = basis.clone();
        eintrag(&mut hier, "Neu hier");
        setzen(&mut hier, &b, "UserName", "gleich");

        let mut ergebnis = hier.clone();
        crate::database::merge(&mut ergebnis, &datei).unwrap();
        assert!(finden(&basis, &hier, &datei, &ergebnis).is_empty(), "A nur extern, B gleich geändert");

        // Jetzt ändert auch die App A — anders.
        setzen_um(&mut hier, &a, "UserName", "hier", 20);
        let mut ergebnis = hier.clone();
        crate::database::merge(&mut ergebnis, &datei).unwrap();
        let k = finden(&basis, &hier, &datei, &ergebnis);
        assert_eq!(k.len(), 1);
        assert_eq!(k[0].id, a);
        assert!(k[0].here.iter().any(|f| f.name == "Benutzername"));
        assert!(k[0].file.iter().any(|f| f.name == "Adresse"));
    }

    /// Beide Seiten in derselben Sekunde: Die Bibliothek bricht dann ab. Der
    /// Abgleich geht trotzdem durch, die App gilt — und es ist ein Konflikt.
    #[test]
    fn dieselbe_sekunde_bricht_nicht_ab() {
        let mut basis = Database::new();
        let a = eintrag(&mut basis, "A");
        let mut datei = basis.clone();
        setzen_um(&mut datei, &a, "URL", "https://extern", 10);
        let mut hier = basis.clone();
        setzen_um(&mut hier, &a, "URL", "https://hier", 10);
        // Auf die Sekunde gleich (die Bibliothek speichert ganze Sekunden).
        let t = datei.iter_all_entries().find(|e| e.id().uuid().to_string() == a).unwrap().times.last_modification;
        let id = hier.iter_all_entries().find(|e| e.id().uuid().to_string() == a).unwrap().id();
        hier.entry_mut(id).unwrap().times.last_modification = t;

        let mut jetzt = hier.clone();
        crate::database::merge(&mut jetzt, &datei).unwrap();
        assert_eq!(feld(&jetzt, &a, "URL").as_deref(), Some("https://hier"));
        let k = finden(&basis, &hier, &datei, &jetzt);
        assert_eq!(k.len(), 1);
        assert_eq!(k[0].winner, "hier");
    }

    /// Die Wahl setzt den Eintrag auf genau die gewählte Fassung.
    #[test]
    fn entscheiden_setzt_die_gewaehlte_fassung() {
        let mut basis = Database::new();
        let a = eintrag(&mut basis, "A");
        let mut datei = basis.clone();
        setzen_um(&mut datei, &a, "URL", "https://extern", 10);
        let mut hier = basis.clone();
        setzen_um(&mut hier, &a, "URL", "https://hier", 20);

        let mut jetzt = hier.clone();
        crate::database::merge(&mut jetzt, &datei).unwrap();
        let k = finden(&basis, &hier, &datei, &jetzt);
        assert_eq!(k.len(), 1);

        let mut offen = Vec::new();
        merken(&mut offen, k.clone(), hier.clone(), datei.clone());
        entscheiden(&mut jetzt, &mut offen, &a, "hier").unwrap();
        assert_eq!(feld(&jetzt, &a, "URL").as_deref(), Some("https://hier"));
        assert!(offen.is_empty());

        merken(&mut offen, k, hier, datei);
        entscheiden(&mut jetzt, &mut offen, &a, "extern").unwrap();
        assert_eq!(feld(&jetzt, &a, "URL").as_deref(), Some("https://extern"));
    }
}
