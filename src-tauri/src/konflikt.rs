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
//!
//! # Wahl je Feld
//!
//! Gibt es den Eintrag auf beiden Seiten noch, nennt der Konflikt jedes
//! Feld, in dem sich die Fassungen unterscheiden ([`felder`]), und wer es
//! seit der Basis geändert hat. Die Wahl `felder` setzt den Eintrag aus
//! beiden Fassungen zusammen: je Feld die Seite, die der Nutzer nennt.
//!
//! # Ohne Rückfrage
//!
//! Hat jedes verschiedene Feld nur eine Seite geändert, gibt es nichts zu
//! entscheiden: [`selbst_loesen`] setzt den Eintrag aus beiden Fassungen
//! zusammen, und der Konflikt bleibt nicht offen. Zur Wahl stehen nur
//! Einträge, bei denen beide Seiten dasselbe Feld oder denselben Anhang
//! verschieden geändert haben oder eine Seite gelöscht hat.
//!
//! # Ordner
//!
//! Für Ordner gilt dasselbe mit Name und Notizen ([`finden_ordner`]).
//! Angaben zur Ansicht, etwa ob ein Ordner aufgeklappt ist, sind kein
//! Konflikt.

use std::collections::HashMap;
use std::sync::Arc;

use keepass::db::{EntryRef, GroupRef, Value};
use keepass::Database;

use crate::dto;

const ORDNER: &str = "ordner";
const TAGS: &str = "tags";
const FELD: &str = "feld:";
const ANHANG: &str = "anhang:";

const EINTRAG: &str = "eintrag";
const ORDNER_ART: &str = "ordner";

/// Die Angaben eines Ordners, die zur Wahl stehen: Kennung und Name für
/// die Oberfläche.
const ORDNERFELDER: [(&str, &str); 2] = [("feld:name", "Name"), ("feld:notizen", "Notizen")];

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
            kind: EINTRAG.to_string(),
            name: if eigen.name.is_empty() { aus_datei.name.clone() } else { eigen.name.clone() },
            folder: eigen.folder.clone(),
            here_kind: eigen.kind.clone(),
            here: eigen.fields.clone(),
            file_kind: aus_datei.kind.clone(),
            file: aus_datei.fields.clone(),
            winner: winner.to_string(),
            fields: felder(basis, hier, datei, &eigen.id, winner),
        });
    }
    out.extend(finden_ordner(basis, hier, datei, ergebnis));
    out.sort_by_key(|c| c.name.to_lowercase());
    out
}

fn ordner<'a>(db: &'a Database, uuid: &str) -> Option<GroupRef<'a>> {
    db.iter_all_groups().find(|g| g.id().uuid().to_string() == uuid)
}

fn ordnerwert(g: &GroupRef<'_>, key: &str) -> String {
    match key {
        "feld:name" => g.name.clone(),
        _ => g.notes.clone().unwrap_or_default(),
    }
}

/// Findet die Ordner, deren Name oder Notizen beide Seiten seit `basis`
/// geändert haben, und verschieden.
fn finden_ordner(basis: &Database, hier: &Database, datei: &Database, ergebnis: &Database) -> Vec<dto::Conflict> {
    let mut out = Vec::new();
    for h in hier.iter_all_groups() {
        let uuid = h.id().uuid().to_string();
        let (Some(b), Some(d)) = (ordner(basis, &uuid), ordner(datei, &uuid)) else { continue };
        let anders = |a: &GroupRef<'_>, b: &GroupRef<'_>| ORDNERFELDER.iter().any(|(k, _)| ordnerwert(a, k) != ordnerwert(b, k));
        if !anders(&h, &b) || !anders(&d, &b) || !anders(&h, &d) {
            continue;
        }
        let winner = match ordner(ergebnis, &uuid) {
            Some(e) if anders(&e, &h) => "extern",
            _ => "hier",
        };
        let fields = ORDNERFELDER
            .iter()
            .filter_map(|(k, name)| {
                let (wh, wd, wb) = (ordnerwert(&h, k), ordnerwert(&d, k), ordnerwert(&b, k));
                (wh != wd).then(|| {
                    let (changed, pick) = match (wh != wb, wd != wb) {
                        (true, false) => ("hier", "hier"),
                        (false, true) => ("extern", "extern"),
                        _ => ("beide", winner),
                    };
                    dto::ConflictField {
                        key: (*k).to_string(),
                        name: (*name).to_string(),
                        secret: false,
                        here: Some(wh),
                        file: Some(wd),
                        changed: changed.to_string(),
                        pick: pick.to_string(),
                    }
                })
            })
            .collect();
        out.push(dto::Conflict {
            id: uuid,
            kind: ORDNER_ART.to_string(),
            name: h.name.clone(),
            folder: h.parent().map(|p| crate::state::folder_path(hier, p.id())).unwrap_or_default(),
            here_kind: "geaendert".to_string(),
            here: Vec::new(),
            file_kind: "geaendert".to_string(),
            file: Vec::new(),
            winner: winner.to_string(),
            fields,
        });
    }
    out
}

/// Setzt Name und Notizen des Ordners: je Feld von der Seite, die `seite`
/// nennt.
fn ordner_entscheiden(jetzt: &mut Database, o: &Offen, seite: impl Fn(&dto::ConflictField) -> String) -> Result<(), String> {
    let uuid = o.info.id.as_str();
    let id = ordner(jetzt, uuid).ok_or("Den Ordner gibt es nicht mehr.")?.id();
    let mut werte = Vec::new();
    for f in &o.info.fields {
        let quelle = if seite(f) == "extern" { &o.datei } else { &o.hier };
        let g = ordner(quelle, uuid).ok_or("Den Ordner gibt es nicht mehr.")?;
        werte.push((f.key.clone(), ordnerwert(&g, &f.key)));
    }
    let mut g = jetzt.group_mut(id).ok_or("Den Ordner gibt es nicht mehr.")?;
    for (key, wert) in werte {
        match key.as_str() {
            "feld:name" => g.name = wert,
            _ => g.notes = (!wert.is_empty()).then_some(wert),
        }
    }
    g.times.last_modification = Some(keepass::db::Times::now());
    Ok(())
}

fn eintrag<'a>(db: &'a Database, uuid: &str) -> Option<EntryRef<'a>> {
    db.iter_all_entries().find(|e| e.id().uuid().to_string() == uuid)
}

fn ordner_von(db: &Database, e: &EntryRef<'_>) -> String {
    crate::state::folder_path(db, e.parent().id())
}

fn tags_von(e: &EntryRef<'_>) -> Vec<String> {
    let mut tags = e.tags.clone();
    tags.sort();
    tags
}

/// Die Felder, in denen sich `hier` und `datei` beim Eintrag `uuid`
/// unterscheiden: alle Textfelder, der Ordner und die Schlagworte. Leer,
/// wenn es den Eintrag auf einer der beiden Seiten nicht gibt.
fn felder(basis: &Database, hier: &Database, datei: &Database, uuid: &str, winner: &str) -> Vec<dto::ConflictField> {
    let (Some(h), Some(d)) = (eintrag(hier, uuid), eintrag(datei, uuid)) else { return Vec::new() };
    let b = eintrag(basis, uuid);

    // Wer hat geändert, und welche Seite wird vorgeschlagen.
    let wer = |hier_anders: bool, datei_anders: bool| match (hier_anders, datei_anders) {
        (true, false) => ("hier", "hier"),
        (false, true) => ("extern", "extern"),
        _ => ("beide", winner),
    };

    let mut schluessel: Vec<&String> = h.fields.keys().chain(d.fields.keys()).collect();
    schluessel.sort();
    schluessel.dedup();
    // Die bekannten Felder zuerst, in der Reihenfolge der Eingabemaske.
    let rang = |k: &str| match k {
        "Title" => 0,
        "UserName" => 1,
        "Password" => 2,
        "URL" => 3,
        "otp" => 4,
        "Notes" => 5,
        _ => 6,
    };
    schluessel.sort_by_key(|k| rang(k));

    let mut out = Vec::new();
    for k in schluessel {
        let (wh, wd) = (h.get(k).unwrap_or_default(), d.get(k).unwrap_or_default());
        if wh == wd {
            continue;
        }
        let wb = b.as_ref().and_then(|b| b.get(k)).unwrap_or_default();
        let (changed, pick) = wer(wh != wb, wd != wb);
        let secret = k == "Password"
            || k == "otp"
            || h.fields.get(k).is_some_and(|v| v.is_protected())
            || d.fields.get(k).is_some_and(|v| v.is_protected());
        let name = match k.as_str() {
            "Password" => "Passwort",
            "otp" => "Einmalcode",
            andere => crate::versions::FELDER.iter().find(|(_, s)| *s == andere).map_or(andere, |(n, _)| n),
        };
        out.push(dto::ConflictField {
            key: format!("{FELD}{k}"),
            name: name.to_string(),
            secret,
            here: (!secret).then(|| wh.to_string()),
            file: (!secret).then(|| wd.to_string()),
            changed: changed.to_string(),
            pick: pick.to_string(),
        });
    }

    let (oh, od) = (ordner_von(hier, &h), ordner_von(datei, &d));
    if oh != od {
        let ob = b.as_ref().map(|b| ordner_von(basis, b)).unwrap_or_default();
        let (changed, pick) = wer(oh != ob, od != ob);
        out.push(dto::ConflictField {
            key: ORDNER.to_string(),
            name: "Ordner".to_string(),
            secret: false,
            here: Some(oh),
            file: Some(od),
            changed: changed.to_string(),
            pick: pick.to_string(),
        });
    }

    let (th, td) = (tags_von(&h), tags_von(&d));
    if th != td {
        let tb = b.as_ref().map(tags_von).unwrap_or_default();
        let (changed, pick) = wer(th != tb, td != tb);
        out.push(dto::ConflictField {
            key: TAGS.to_string(),
            name: "Schlagworte".to_string(),
            secret: false,
            here: Some(th.join(", ")),
            file: Some(td.join(", ")),
            changed: changed.to_string(),
            pick: pick.to_string(),
        });
    }

    let (ah, ad) = (anhaenge_von(&h), anhaenge_von(&d));
    let ab = b.as_ref().map(anhaenge_von).unwrap_or_default();
    let mut namen: Vec<&String> = ah.keys().chain(ad.keys()).collect();
    namen.sort();
    namen.dedup();
    for name in namen {
        let inhalt = |von: &HashMap<String, Value<Vec<u8>>>| von.get(name).map(|v| v.get().clone());
        let (wh, wd, wb) = (inhalt(&ah), inhalt(&ad), inhalt(&ab));
        if wh == wd {
            continue;
        }
        let (changed, pick) = wer(wh != wb, wd != wb);
        out.push(dto::ConflictField {
            key: format!("{ANHANG}{name}"),
            name: format!("Anhang: {name}"),
            secret: false,
            here: Some(wh.map(|w| groesse(w.len())).unwrap_or_default()),
            file: Some(wd.map(|w| groesse(w.len())).unwrap_or_default()),
            changed: changed.to_string(),
            pick: pick.to_string(),
        });
    }

    out
}

/// Die Größe eines Anhangs für die Oberfläche.
fn groesse(bytes: usize) -> String {
    match bytes {
        b if b < 1024 => format!("{b} B"),
        b if b < 1024 * 1024 => format!("{:.1} kB", b as f64 / 1024.0),
        b => format!("{:.1} MB", b as f64 / (1024.0 * 1024.0)),
    }
}

/// Die Anhänge, die der Eintrag nach der Wahl haben soll: die der Seite,
/// die `seite` je Feld nennt; wo sich die Seiten nicht unterscheiden, die
/// von `hier`. `None`, wenn es den Eintrag auf der gewählten Seite nicht gibt.
fn anhaenge_nach_wahl(o: &Offen, wahl: &str, seite: impl Fn(&dto::ConflictField) -> String) -> Option<HashMap<String, Value<Vec<u8>>>> {
    let uuid = o.info.id.as_str();
    let von = |db: &Database| eintrag(db, uuid).map(|e| anhaenge_von(&e));
    match wahl {
        "hier" => von(&o.hier),
        "extern" => von(&o.datei),
        _ => {
            let (mut ziel, fremd) = (von(&o.hier)?, von(&o.datei)?);
            for f in &o.info.fields {
                let Some(name) = f.key.strip_prefix(ANHANG) else { continue };
                if seite(f) != "extern" {
                    continue;
                }
                match fremd.get(name) {
                    Some(wert) => ziel.insert(name.to_string(), wert.clone()),
                    None => ziel.remove(name),
                };
            }
            Some(ziel)
        }
    }
}

/// Gibt dem Eintrag genau die Anhänge `ziel`.
fn anhaenge_setzen(jetzt: &mut Database, uuid: &str, ziel: HashMap<String, Value<Vec<u8>>>) {
    let Some(e) = eintrag(jetzt, uuid) else { return };
    let (id, sind) = (e.id(), anhaenge_von(&e));
    let gleich = sind.len() == ziel.len() && sind.iter().all(|(n, w)| ziel.get(n).is_some_and(|z| z.get() == w.get()));
    if gleich {
        return;
    }
    let Some(mut e) = jetzt.entry_mut(id) else { return };
    for name in sind.keys() {
        e.remove_attachment_by_name(name);
    }
    for (name, wert) in ziel {
        e.add_attachment(name, wert);
    }
}

/// Die Fassung von `hier`, in der die Felder mit der Wahl `extern` aus
/// `datei` stammen. Für ein Feld ohne Angabe in `wahl` gilt der Vorschlag.
fn gemischt(o: &Offen, wahl: &HashMap<String, String>) -> Result<Database, String> {
    let uuid = o.info.id.as_str();
    let d = eintrag(&o.datei, uuid).ok_or("Der Eintrag ist in der Datei gelöscht.")?;
    let mut misch = (*o.hier).clone();
    let id = eintrag(&misch, uuid).ok_or("Der Eintrag ist hier gelöscht.")?.id();

    for f in &o.info.fields {
        if wahl.get(&f.key).unwrap_or(&f.pick) != "extern" {
            continue;
        }
        if f.key == ORDNER {
            let ziel = crate::state::ensure_group(&mut misch, &ordner_von(&o.datei, &d));
            misch
                .entry_mut(id)
                .ok_or("Der Eintrag ist nicht mehr da.")?
                .move_to(ziel)
                .map_err(|e| format!("Verschieben fehlgeschlagen: {e}"))?;
            continue;
        }
        let mut e = misch.entry_mut(id).ok_or("Der Eintrag ist nicht mehr da.")?;
        if f.key == TAGS {
            e.tags = d.tags.clone();
        } else if let Some(k) = f.key.strip_prefix(FELD) {
            // Anhänge setzt `anhaenge_nach_wahl`.
            match d.fields.get(k) {
                Some(wert) => e.fields.insert(k.to_string(), wert.clone()),
                None => e.fields.remove(k),
            };
        }
    }
    Ok(misch)
}

fn anhaenge_von(e: &EntryRef<'_>) -> HashMap<String, Value<Vec<u8>>> {
    e.attachments_named().map(|(name, a)| (name.to_string(), a.data.clone())).collect()
}

/// Lässt sich der Konflikt ohne Rückfrage lösen? Ja, wenn es Eintrag oder
/// Ordner auf beiden Seiten gibt und jedes verschiedene Feld nur von einer
/// Seite geändert wurde.
fn loesbar(o: &Offen) -> bool {
    let beide_da = if o.info.kind == ORDNER_ART {
        true
    } else {
        eintrag(&o.hier, &o.info.id).is_some() && eintrag(&o.datei, &o.info.id).is_some()
    };
    beide_da && o.info.fields.iter().all(|f| f.changed != "beide")
}

/// Löst die offenen Konflikte, die keine Entscheidung brauchen: Jedes Feld
/// bekommt den Wert der Seite, die es geändert hat. Zurück: wie viele.
pub fn selbst_loesen(jetzt: &mut Database, offen: &mut Vec<Offen>) -> usize {
    let ids: Vec<String> = offen.iter().filter(|o| loesbar(o)).map(|o| o.info.id.clone()).collect();
    ids.iter().filter(|id| entscheiden(jetzt, offen, id, "felder", &HashMap::new()).is_ok()).count()
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

/// Entscheidet einen Konflikt: Eintrag oder Ordner bekommt die gewählte
/// Fassung — `hier`, `extern` oder `felder`. Hatte die gewählte Seite den
/// Eintrag gelöscht, wird er gelöscht. Bei `felder` nennt `felder` je Feld
/// die Seite; ohne Angabe gilt der Vorschlag.
pub fn entscheiden(
    jetzt: &mut Database,
    offen: &mut Vec<Offen>,
    id: &str,
    wahl: &str,
    felder: &HashMap<String, String>,
) -> Result<(), String> {
    let i = offen.iter().position(|o| o.info.id == id).ok_or("Diesen Konflikt gibt es nicht mehr.")?;
    let o = &offen[i];
    let seite = |f: &dto::ConflictField| match wahl {
        "felder" => felder.get(&f.key).unwrap_or(&f.pick).clone(),
        ganz => ganz.to_string(),
    };
    if !matches!(wahl, "hier" | "extern" | "felder") {
        return Err(format!("Unbekannte Wahl: {wahl}"));
    }
    if o.info.kind == ORDNER_ART {
        ordner_entscheiden(jetzt, o, seite)?;
    } else {
        match wahl {
            "hier" => crate::versions::eintrag_zurueck(jetzt, &o.hier, id)?,
            "extern" => crate::versions::eintrag_zurueck(jetzt, &o.datei, id)?,
            _ => crate::versions::eintrag_zurueck(jetzt, &gemischt(o, felder)?, id)?,
        }
        if let Some(ziel) = anhaenge_nach_wahl(o, wahl, seite) {
            anhaenge_setzen(jetzt, id, ziel);
        }
    }
    offen.remove(i);
    Ok(())
}

/// Der Klartext eines Feldes in einer der beiden Fassungen (`hier` oder
/// `extern`), zum Vergleichen vor der Wahl.
pub fn aufdecken(offen: &[Offen], id: &str, key: &str, seite: &str) -> Result<String, String> {
    let o = offen.iter().find(|o| o.info.id == id).ok_or("Diesen Konflikt gibt es nicht mehr.")?;
    let feld = key.strip_prefix(FELD).ok_or("Dieses Feld hat keinen Text.")?;
    let quelle = if seite == "extern" { &o.datei } else { &o.hier };
    let e = eintrag(quelle, id).ok_or("Den Eintrag gibt es auf dieser Seite nicht.")?;
    Ok(e.get(feld).unwrap_or_default().to_string())
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

    /// Ändert ein Feld, `sek` Sekunden nach jetzt, damit die Seiten
    /// unterschiedlich alt sind.
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

    /// Extern zwei neue Einträge und einer geändert, hier ein neuer: kein
    /// Konflikt. Erst wenn beide Seiten denselben Eintrag verschieden ändern,
    /// ist es einer.
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
    /// Abgleich geht trotzdem durch, die App gilt, und es ist ein Konflikt.
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
        entscheiden(&mut jetzt, &mut offen, &a, "hier", &HashMap::new()).unwrap();
        assert_eq!(feld(&jetzt, &a, "URL").as_deref(), Some("https://hier"));
        assert!(offen.is_empty());

        merken(&mut offen, k, hier, datei);
        entscheiden(&mut jetzt, &mut offen, &a, "extern", &HashMap::new()).unwrap();
        assert_eq!(feld(&jetzt, &a, "URL").as_deref(), Some("https://extern"));
    }

    /// Hier der Benutzername, in der Datei die Adresse, der Titel auf beiden
    /// Seiten: Der Vorschlag nimmt von jeder Seite, was nur sie geändert
    /// hat; die Wahl je Feld setzt den Eintrag aus beiden zusammen.
    #[test]
    fn felder_lassen_sich_einzeln_waehlen() {
        let mut basis = Database::new();
        let a = eintrag(&mut basis, "A");
        let mut datei = basis.clone();
        setzen_um(&mut datei, &a, "URL", "https://extern", 10);
        setzen_um(&mut datei, &a, "Title", "A extern", 10);
        let mut hier = basis.clone();
        setzen_um(&mut hier, &a, "UserName", "hier", 20);
        setzen_um(&mut hier, &a, "Title", "A hier", 20);

        let mut jetzt = hier.clone();
        crate::database::merge(&mut jetzt, &datei).unwrap();
        let k = finden(&basis, &hier, &datei, &jetzt);
        assert_eq!(k.len(), 1);
        let f = |key: &str| k[0].fields.iter().find(|f| f.key == key).unwrap();
        assert_eq!((f("feld:UserName").changed.as_str(), f("feld:UserName").pick.as_str()), ("hier", "hier"));
        assert_eq!((f("feld:URL").changed.as_str(), f("feld:URL").pick.as_str()), ("extern", "extern"));
        assert_eq!((f("feld:Title").changed.as_str(), f("feld:Title").pick.as_str()), ("beide", "hier"));
        assert_eq!(k[0].fields.len(), 3);

        // Ohne Angaben gilt der Vorschlag; der Titel ausdrücklich aus der Datei.
        let mut offen = Vec::new();
        merken(&mut offen, k, hier, datei);
        let wahl = HashMap::from([("feld:Title".to_string(), "extern".to_string())]);
        entscheiden(&mut jetzt, &mut offen, &a, "felder", &wahl).unwrap();
        assert_eq!(feld(&jetzt, &a, "UserName").as_deref(), Some("hier"));
        assert_eq!(feld(&jetzt, &a, "URL").as_deref(), Some("https://extern"));
        assert_eq!(feld(&jetzt, &a, "Title").as_deref(), Some("A extern"));
        assert!(offen.is_empty());
    }

    /// Geheimnisse stehen ohne Werte im Konflikt und lassen sich trotzdem
    /// je Feld wählen.
    #[test]
    fn passwort_ohne_werte_waehlbar() {
        let mut basis = Database::new();
        let a = eintrag(&mut basis, "A");
        let mut datei = basis.clone();
        setzen_um(&mut datei, &a, "Password", "extern-geheim", 10);
        let mut hier = basis.clone();
        setzen_um(&mut hier, &a, "Password", "hier-geheim", 20);

        let mut jetzt = hier.clone();
        crate::database::merge(&mut jetzt, &datei).unwrap();
        let k = finden(&basis, &hier, &datei, &jetzt);
        let f = &k[0].fields[0];
        assert!(f.secret && f.here.is_none() && f.file.is_none());

        let mut offen = Vec::new();
        merken(&mut offen, k, hier, datei);
        let wahl = HashMap::from([("feld:Password".to_string(), "extern".to_string())]);
        entscheiden(&mut jetzt, &mut offen, &a, "felder", &wahl).unwrap();
        assert_eq!(feld(&jetzt, &a, "Password").as_deref(), Some("extern-geheim"));
    }

    /// Ein Ordner mit derselben Änderungszeit, aber anderem Inhalt auf
    /// beiden Seiten: Der Abgleich geht durch, in beide Richtungen.
    #[test]
    fn ordner_mit_derselben_zeit_bricht_nicht_ab() {
        let mut basis = Database::new();
        eintrag(&mut basis, "A");
        let g = ensure_group(&mut basis, "Allgemein");
        let mut datei = basis.clone();
        datei.group_mut(g).unwrap().is_expanded = !basis.group(g).unwrap().is_expanded;
        let mut hier = basis.clone();
        eintrag(&mut hier, "Neu hier");

        assert!(hier.clone().merge(&datei).is_err(), "die Bibliothek allein bricht hier ab");

        let mut jetzt = hier.clone();
        let (_, hier_voraus) = crate::database::merge(&mut jetzt, &datei).unwrap();
        assert!(hier_voraus, "der neue Eintrag fehlt der Datei");
        assert!(finden(&basis, &hier, &datei, &jetzt).is_empty());

        // Der zusammengeführte Stand lässt sich danach ohne Abbruch abgleichen.
        let mut wieder = jetzt.clone();
        crate::database::merge(&mut wieder, &datei).unwrap();
    }

    /// Hier der Benutzername, in der Datei die Adresse: gelöst ohne
    /// Rückfrage. Ändern beide den Titel, bleibt der Konflikt offen.
    #[test]
    fn verschiedene_felder_loesen_sich_selbst() {
        let mut basis = Database::new();
        let a = eintrag(&mut basis, "A");
        let mut datei = basis.clone();
        setzen_um(&mut datei, &a, "URL", "https://extern", 10);
        let mut hier = basis.clone();
        setzen_um(&mut hier, &a, "UserName", "hier", 20);

        let mut jetzt = hier.clone();
        crate::database::merge(&mut jetzt, &datei).unwrap();
        let mut offen = Vec::new();
        merken(&mut offen, finden(&basis, &hier, &datei, &jetzt), hier.clone(), datei.clone());
        assert_eq!(selbst_loesen(&mut jetzt, &mut offen), 1);
        assert!(offen.is_empty());
        assert_eq!(feld(&jetzt, &a, "UserName").as_deref(), Some("hier"));
        assert_eq!(feld(&jetzt, &a, "URL").as_deref(), Some("https://extern"));

        setzen_um(&mut datei, &a, "Title", "A extern", 10);
        setzen_um(&mut hier, &a, "Title", "A hier", 20);
        let mut jetzt = hier.clone();
        crate::database::merge(&mut jetzt, &datei).unwrap();
        merken(&mut offen, finden(&basis, &hier, &datei, &jetzt), hier, datei);
        assert_eq!(selbst_loesen(&mut jetzt, &mut offen), 0);
        assert_eq!(offen.len(), 1);
    }

    /// Beide Seiten nennen den Ordner um: ein Konflikt zur Wahl, auch bei
    /// derselben Änderungszeit. Nur eine Seite: keiner.
    #[test]
    fn ordner_beidseitig_umbenannt_ist_ein_konflikt() {
        let mut basis = Database::new();
        eintrag(&mut basis, "A");
        let g = ensure_group(&mut basis, "Allgemein");
        let uuid = g.uuid().to_string();
        let name = |db: &Database| db.group(g).unwrap().name.clone();
        let nennen = |db: &mut Database, neu: &str, sek: i64| {
            let mut o = db.group_mut(g).unwrap();
            o.name = neu.to_string();
            o.times.last_modification = Some(keepass::db::Times::now() + chrono::Duration::seconds(sek));
        };

        let mut datei = basis.clone();
        nennen(&mut datei, "Extern", 10);
        let hier = basis.clone();
        let mut jetzt = hier.clone();
        crate::database::merge(&mut jetzt, &datei).unwrap();
        assert!(finden(&basis, &hier, &datei, &jetzt).is_empty(), "nur die Datei hat umbenannt");
        assert_eq!(name(&jetzt), "Extern");

        let mut hier = basis.clone();
        nennen(&mut hier, "Hier", 10);
        let mut jetzt = hier.clone();
        crate::database::merge(&mut jetzt, &datei).unwrap();
        let k = finden(&basis, &hier, &datei, &jetzt);
        assert_eq!(k.len(), 1);
        assert_eq!((k[0].kind.as_str(), k[0].id.as_str(), k[0].winner.as_str()), ("ordner", uuid.as_str(), "hier"));
        assert_eq!(k[0].fields[0].changed, "beide");

        let mut offen = Vec::new();
        merken(&mut offen, k, hier, datei);
        assert_eq!(selbst_loesen(&mut jetzt, &mut offen), 0);
        entscheiden(&mut jetzt, &mut offen, &uuid, "extern", &HashMap::new()).unwrap();
        assert_eq!(name(&jetzt), "Extern");
        assert!(offen.is_empty());
    }

    /// Anhänge stehen je Datei zur Wahl; ein nur auf einer Seite neuer
    /// Anhang kommt ohne Rückfrage dazu.
    #[test]
    fn anhaenge_je_datei() {
        let mut basis = Database::new();
        let a = eintrag(&mut basis, "A");
        let id = basis.iter_all_entries().next().unwrap().id();
        basis.entry_mut(id).unwrap().add_attachment("plan.txt", Value::unprotected(b"alt".to_vec()));
        let anhang = |db: &Database, name: &str| {
            db.entry(id).and_then(|e| e.attachment_by_name(name).map(|a| a.data.get().clone()))
        };

        let mut datei = basis.clone();
        setzen_um(&mut datei, &a, "URL", "https://extern", 10);
        datei.entry_mut(id).unwrap().add_attachment("neu.txt", Value::unprotected(b"neu".to_vec()));
        let mut hier = basis.clone();
        setzen_um(&mut hier, &a, "UserName", "hier", 20);

        let mut jetzt = hier.clone();
        crate::database::merge(&mut jetzt, &datei).unwrap();
        let mut offen = Vec::new();
        merken(&mut offen, finden(&basis, &hier, &datei, &jetzt), hier.clone(), datei.clone());
        assert_eq!(selbst_loesen(&mut jetzt, &mut offen), 1);
        assert_eq!(anhang(&jetzt, "neu.txt").as_deref(), Some(b"neu".as_slice()));
        assert_eq!(anhang(&jetzt, "plan.txt").as_deref(), Some(b"alt".as_slice()));

        // Beide ersetzen denselben Anhang verschieden: zur Wahl.
        datei.entry_mut(id).unwrap().remove_attachment_by_name("plan.txt");
        datei.entry_mut(id).unwrap().add_attachment("plan.txt", Value::unprotected(b"extern".to_vec()));
        hier.entry_mut(id).unwrap().remove_attachment_by_name("plan.txt");
        hier.entry_mut(id).unwrap().add_attachment("plan.txt", Value::unprotected(b"von hier".to_vec()));
        let mut jetzt = hier.clone();
        crate::database::merge(&mut jetzt, &datei).unwrap();
        let k = finden(&basis, &hier, &datei, &jetzt);
        assert_eq!(k[0].fields.iter().find(|f| f.key == "anhang:plan.txt").unwrap().changed, "beide");
        merken(&mut offen, k, hier, datei);
        assert_eq!(selbst_loesen(&mut jetzt, &mut offen), 0);
        let wahl = HashMap::from([("anhang:plan.txt".to_string(), "extern".to_string())]);
        entscheiden(&mut jetzt, &mut offen, &a, "felder", &wahl).unwrap();
        assert_eq!(anhang(&jetzt, "plan.txt").as_deref(), Some(b"extern".as_slice()));
        assert_eq!(anhang(&jetzt, "neu.txt").as_deref(), Some(b"neu".as_slice()));
        assert_eq!(feld(&jetzt, &a, "UserName").as_deref(), Some("hier"));
    }

    /// Beide Fassungen eines Passworts lassen sich vor der Wahl aufdecken.
    #[test]
    fn passwort_beider_seiten_aufdecken() {
        let mut basis = Database::new();
        let a = eintrag(&mut basis, "A");
        let mut datei = basis.clone();
        setzen_um(&mut datei, &a, "Password", "extern-geheim", 10);
        let mut hier = basis.clone();
        setzen_um(&mut hier, &a, "Password", "hier-geheim", 20);
        let mut jetzt = hier.clone();
        crate::database::merge(&mut jetzt, &datei).unwrap();
        let mut offen = Vec::new();
        merken(&mut offen, finden(&basis, &hier, &datei, &jetzt), hier, datei);
        assert_eq!(aufdecken(&offen, &a, "feld:Password", "hier").unwrap(), "hier-geheim");
        assert_eq!(aufdecken(&offen, &a, "feld:Password", "extern").unwrap(), "extern-geheim");
    }
}
