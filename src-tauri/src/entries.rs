//! Einträge und Ordner ändern.
//!
//! # Was die Reihenfolge angeht
//!
//! Innerhalb einer Gruppe liegen Einträge in KDBX in einer festen Reihenfolge,
//! die `keepass` aber nicht nach außen gibt (`Group::entries` ist
//! crate-intern). `vault_reorder_entry` und `vault_reorder_folder` setzen
//! deshalb nur den **Ordner** des Ziels durch — das Einsortieren an eine
//! bestimmte Stelle innerhalb des Ordners bleibt vorerst folgenlos.
//!
//! Das ist der sichtbare Teil des Ziehens und Fallenlassens: Etwas in einen
//! anderen Ordner zu ziehen wirkt, die genaue Position darin nicht.

use keepass::db::{EntryId, GroupId};

use crate::database::{apply_plain_fields, entry_id_of};
use crate::dto;
use crate::state::{
    ensure_group, ensure_recycle_bin, find_group, is_recycled, recycle_bin, VaultState, ROOT_LABEL,
};
use crate::Vault;

fn lock<'a>(state: &tauri::State<'a, Vault>) -> Result<std::sync::MutexGuard<'a, VaultState>, String> {
    let mut vault = state.inner().lock().map_err(|_| "Kern blockiert.".to_string())?;
    vault.touch();
    Ok(vault)
}

/* =========================================================
   Einträge
   ========================================================= */

#[tauri::command]
pub fn vault_save_entry(
    state: tauri::State<'_, Vault>,
    entry: dto::Entry,
) -> Result<dto::Entry, String> {
    let mut vault = lock(&state)?;

    // Die Werte holen, solange der Zustand noch unangetastet ist.
    let password = entry
        .password_token
        .as_ref()
        .and_then(|t| vault.secrets.get(t))
        .map(|v| v.to_string());

    let totp = entry
        .totp_token
        .as_ref()
        .and_then(|t| vault.secrets.get(t))
        .map(|v| v.to_string());

    let (entry_id, uuid) = {
        let db = vault.database_mut()?;
        let target = ensure_group(db, &entry.folder);

        let existing = entry.id.as_deref().and_then(|id| entry_id_of(db, id));

        // Den bisherigen Ordner ablesen, solange die Datenbank noch
        // unveränderlich ausgeliehen ist — `EntryMut` gibt ihn nicht her.
        let previous = existing.and_then(|id| db.entry(id).map(|e| e.parent().id()));

        // Erst die Kennung bestimmen, dann den Eintrag frisch holen: Ein
        // `EntryMut` aus `add_entry()` lebt nur so lange wie die Gruppe,
        // aus der es stammt.
        let id = match existing {
            Some(id) => {
                if previous != Some(target) {
                    let mut node = db.entry_mut(id).ok_or("Eintrag verschwunden.")?;
                    node.move_to(target)
                        .map_err(|e| format!("Verschieben fehlgeschlagen: {e}"))?;
                }
                id
            }
            None => {
                let mut group = db.group_mut(target).ok_or("Zielordner verschwunden.")?;
                group.add_entry().id()
            }
        };

        let mut node = db.entry_mut(id).ok_or("Eintrag verschwunden.")?;
        apply_plain_fields(&mut node, &entry);

        match &password {
            Some(value) => node.set_protected(keepass::db::fields::PASSWORD, value.clone()),
            None => { node.fields.remove(keepass::db::fields::PASSWORD); }
        }

        match &totp {
            Some(value) => node.set_protected(keepass::db::fields::OTP, value.clone()),
            None => { node.fields.remove(keepass::db::fields::OTP); }
        }

        (id, node.id().uuid().to_string())
    };

    apply_attachments(&mut vault, entry_id, &entry)?;

    // Die Token an die neue UUID binden, damit sie beim nächsten Auflisten
    // wieder dieselben sind.
    if let Some(token) = &entry.password_token {
        vault.field_tokens.insert((uuid.clone(), "Password".into()), token.clone());
    }
    if let Some(token) = &entry.totp_token {
        vault.field_tokens.insert((uuid.clone(), "otp".into()), token.clone());
    }

    let mut saved = entry;
    saved.id = Some(uuid);
    saved.has_password = password.is_some();
    saved.has_totp = totp.is_some();
    Ok(saved)
}

/// Schreibt einen einzelnen Anhang eines **gespeicherten** Eintrags sofort
/// in die Datenbank — bearbeitet, umbenannt oder neu angelegt.
///
/// Anders als `vault_save_entry` fasst das nur diesen einen Anhang an. Was im
/// Eintragsdialog sonst noch geändert, aber nicht gespeichert wurde, bleibt
/// unberührt.
///
/// `ref` ist entweder ein Verweis in den Zwischenspeicher (neuer Inhalt)
/// oder die Kennung des vorhandenen Anhangs (nur umbenennen). `previous` ist
/// der bisherige Name, falls es einen gab. Zurück kommt die neue Kennung.
#[tauri::command]
pub fn vault_write_attachment(
    state: tauri::State<'_, Vault>,
    #[allow(non_snake_case)] entryId: String,
    name: String,
    r#ref: String,
    previous: Option<String>,
) -> Result<String, String> {
    let mut vault = lock(&state)?;
    write_attachment(&mut vault, &entryId, &name, &r#ref, previous.as_deref())
}

fn write_attachment(
    vault: &mut VaultState,
    entry_uuid: &str,
    name: &str,
    reference: &str,
    previous: Option<&str>,
) -> Result<String, String> {
    use keepass::db::Value;

    if name.trim().is_empty() || name.contains(['/', '\\']) {
        return Err("Der Name darf nicht leer sein und keinen Schrägstrich enthalten.".into());
    }

    let entry_id = entry_id_of(vault.database()?, entry_uuid).ok_or("Eintrag nicht gefunden.")?;

    let bytes = if reference.starts_with(crate::secrets::STAGED_PREFIX) {
        vault
            .staged
            .remove(reference)
            .ok_or("Der Inhalt ist nicht mehr im Zwischenspeicher.")?
            .bytes
    } else {
        let wanted: usize = reference.parse().map_err(|_| "Unbekannter Anhang.".to_string())?;
        let db = vault.database()?;
        let entry = db.entry(entry_id).ok_or("Eintrag nicht gefunden.")?;
        let found = entry
            .attachments_named()
            .find(|(_, a)| a.id().id() == wanted)
            .map(|(_, a)| a.data.get().to_vec());
        found.ok_or("Der Anhang ist nicht mehr da.")?
    };

    let db = vault.database_mut()?;
    let taken = db
        .entry(entry_id)
        .is_some_and(|e| e.attachments_named().any(|(n, _)| n == name));
    if taken && previous != Some(name) {
        return Err(format!("„{name}“ gibt es in diesem Eintrag schon."));
    }

    let mut node = db.entry_mut(entry_id).ok_or("Eintrag nicht gefunden.")?;
    if let Some(old) = previous.filter(|old| *old != name) {
        node.remove_attachment_by_name(old);
    }
    node.times.last_modification = Some(keepass::db::Times::now());
    let id = node.add_attachment(name, Value::Unprotected(bytes)).id().id();
    Ok(id.to_string())
}

/// Bringt die Anhänge des Eintrags auf den Stand, den die Oberfläche meldet.
///
/// Die Liste ist die Wahrheit: Was dort fehlt, wird entfernt; was mit
/// `staged:` beginnt, kommt aus dem Zwischenspeicher neu hinzu. Alles andere
/// steht bereits in der Datenbank und bleibt unangetastet — ein Anhang wird
/// also nicht bei jedem Speichern neu geschrieben.
///
/// Umbenennen: Der Name ist in KDBX der Schlüssel, unter dem der Eintrag
/// seinen Anhang führt. Trägt ein vorhandener Verweis einen anderen Namen als
/// in der Datenbank, wird der Inhalt unter dem neuen Namen neu abgelegt und
/// der alte Name fällt als überzählig weg. Früher fehlte der erste Teil — der
/// Anhang wurde entfernt und nie wieder angelegt.
///
/// Neuer Inhalt unter bekanntem Namen (Bearbeiten) ersetzt den alten, das
/// erledigt `add_attachment` selbst.
fn apply_attachments(
    vault: &mut crate::state::VaultState,
    entry_id: EntryId,
    entry: &dto::Entry,
) -> Result<(), String> {
    use keepass::db::Value;

    // Erst einsammeln, was neu dazukommt — danach ist `vault` ausgeliehen.
    let mut incoming = Vec::new();
    for link in &entry.attachments {
        if !link.reference.starts_with(crate::secrets::STAGED_PREFIX) {
            continue;
        }
        let staged = vault
            .staged
            .remove(&link.reference)
            .ok_or("Der Anhang ist nicht mehr im Zwischenspeicher. Bitte erneut auswählen.")?;
        incoming.push((link.name.clone(), staged.bytes));
    }

    // Umbenannte: Inhalt jetzt sichern, bevor der alte Name entfernt wird.
    {
        let db = vault.database()?;
        if let Some(node) = db.entry(entry_id) {
            let current: std::collections::HashMap<usize, (String, Vec<u8>)> = node
                .attachments_named()
                .map(|(name, att)| (att.id().id(), (name.to_string(), att.data.get().to_vec())))
                .collect();

            for link in &entry.attachments {
                let Ok(id) = link.reference.parse::<usize>() else { continue };
                if let Some((name, bytes)) = current.get(&id) {
                    if *name != link.name {
                        incoming.push((link.name.clone(), bytes.clone()));
                    }
                }
            }
        }
    }

    let keep: std::collections::HashSet<&str> =
        entry.attachments.iter().map(|a| a.name.as_str()).collect();

    // Die Namen der vorhandenen Anhänge kennt nur die unveränderliche Sicht;
    // `EntryMut` gibt sie nicht her. Deshalb erst lesen, dann ändern.
    let db = vault.database_mut()?;
    let obsolete: Vec<String> = db
        .entry(entry_id)
        .map(|node| {
            node.attachments_named()
                .map(|(name, _)| name.to_string())
                .filter(|name| !keep.contains(name.as_str()))
                .collect()
        })
        .unwrap_or_default();

    let mut node = db.entry_mut(entry_id).ok_or("Eintrag verschwunden.")?;

    for name in &obsolete {
        node.remove_attachment_by_name(name);
    }

    for (name, bytes) in incoming {
        node.add_attachment(name, Value::Unprotected(bytes));
    }

    Ok(())
}

/// Löschen in zwei Stufen, wie KeePassXC es macht:
///
///   1. Ein Eintrag außerhalb des Papierkorbs wandert hinein. Er bleibt
///      sichtbar, samt Passwort — nur eben im Papierkorb.
///   2. Ein Eintrag, der schon drin liegt, wird endgültig entfernt. Dabei
///      entsteht ein Löschvermerk in `deleted_objects`, sonst brächte ein
///      Abgleich mit einem anderen Gerät ihn zurück.
#[tauri::command]
pub fn vault_delete_entry(state: tauri::State<'_, Vault>, id: String) -> Result<bool, String> {
    let mut vault = lock(&state)?;
    let db = vault.database_mut()?;

    let Some(entry_id) = entry_id_of(db, &id) else { return Ok(false) };
    let Some(parent) = db.entry(entry_id).map(|e| e.parent().id()) else { return Ok(false) };

    if is_recycled(db, parent) {
        // `track_changes` ist der Weg, der den Löschvermerk schreibt.
        db.entry_mut(entry_id).ok_or("Eintrag verschwunden.")?.track_changes().remove();
        vault.field_tokens.retain(|(uuid, _), _| uuid != &id);
        return Ok(true);
    }

    let bin = ensure_recycle_bin(db);
    db.entry_mut(entry_id)
        .ok_or("Eintrag verschwunden.")?
        .move_to(bin)
        .map_err(|e| format!("Verschieben in den Papierkorb fehlgeschlagen: {e}"))?;
    Ok(true)
}

/// Leert den Papierkorb endgültig.
#[tauri::command]
pub fn vault_empty_recycle_bin(state: tauri::State<'_, Vault>) -> Result<u32, String> {
    let mut vault = lock(&state)?;
    let db = vault.database_mut()?;

    let Some(bin) = recycle_bin(db) else { return Ok(0) };

    let doomed: Vec<_> = db
        .iter_all_entries()
        .filter(|e| is_recycled(db, e.parent().id()))
        .map(|e| (e.id(), e.id().uuid().to_string()))
        .collect();

    let mut gone: Vec<String> = Vec::new();
    for (entry_id, uuid) in doomed {
        if let Some(mut entry) = db.entry_mut(entry_id) {
            entry.track_changes().remove();
            gone.push(uuid);
        }
    }

    // Untergruppen des Papierkorbs mit wegräumen, den Papierkorb selbst nicht.
    let nested: Vec<_> = db
        .iter_all_groups()
        .filter(|g| g.id() != bin && is_recycled(db, g.id()))
        .map(|g| g.id())
        .collect();

    for group in nested {
        if let Some(g) = db.group_mut(group) {
            g.remove();
        }
    }

    // Erst jetzt, wenn die Ausleihe der Datenbank beendet ist.
    vault.field_tokens.retain(|(id, _), _| !gone.contains(id));
    Ok(gone.len() as u32)
}

#[tauri::command]
pub fn vault_move_entry(
    state: tauri::State<'_, Vault>,
    id: String,
    folder: String,
) -> Result<bool, String> {
    let mut vault = lock(&state)?;
    let db = vault.database_mut()?;

    let Some(entry_id) = entry_id_of(db, &id) else { return Ok(false) };
    let target = ensure_group(db, &folder);

    db.entry_mut(entry_id)
        .ok_or("Eintrag verschwunden.")?
        .move_to(target)
        .map_err(|e| format!("Verschieben fehlgeschlagen: {e}"))?;
    Ok(true)
}

/// Übernimmt den Ordner des Bezugseintrags. Siehe Modulkommentar: die
/// Position innerhalb des Ordners bleibt unberührt.
#[tauri::command]
pub fn vault_reorder_entry(
    state: tauri::State<'_, Vault>,
    id: String,
    reference_id: String,
    _position: String,
) -> Result<bool, String> {
    let mut vault = lock(&state)?;
    let db = vault.database_mut()?;

    let (Some(entry_id), Some(reference)) = (entry_id_of(db, &id), entry_id_of(db, &reference_id))
    else {
        return Ok(false);
    };

    let target = db.entry(reference).map(|e| e.parent().id()).ok_or("Bezugseintrag verschwunden.")?;

    db.entry_mut(entry_id)
        .ok_or("Eintrag verschwunden.")?
        .move_to(target)
        .map_err(|e| format!("Verschieben fehlgeschlagen: {e}"))?;
    Ok(true)
}

/* =========================================================
   Ordner
   ========================================================= */

#[tauri::command]
pub fn vault_create_folder(state: tauri::State<'_, Vault>, path: String) -> Result<bool, String> {
    let mut vault = lock(&state)?;
    ensure_group(vault.database_mut()?, &path);
    Ok(true)
}

#[tauri::command]
pub fn vault_rename_folder(
    state: tauri::State<'_, Vault>,
    path: String,
    name: String,
) -> Result<bool, String> {
    if name.trim().is_empty() {
        return Err("Ein Ordner braucht einen Namen.".into());
    }

    let mut vault = lock(&state)?;
    let db = vault.database_mut()?;

    let Some(group) = resolve_editable(db, &path)? else { return Ok(false) };
    db.group_mut(group).ok_or("Ordner verschwunden.")?.name = name;
    Ok(true)
}

#[tauri::command]
pub fn vault_move_folder(
    state: tauri::State<'_, Vault>,
    path: String,
    parent: String,
) -> Result<bool, String> {
    let mut vault = lock(&state)?;
    let db = vault.database_mut()?;

    let Some(group) = resolve_editable(db, &path)? else { return Ok(false) };
    let target = ensure_group(db, &parent);

    db.group_mut(group)
        .ok_or("Ordner verschwunden.")?
        .move_to(target)
        .map_err(|e| format!("Verschieben fehlgeschlagen: {e}"))?;
    Ok(true)
}

/// Löscht einen Ordner in zwei Stufen, genau wie bei Einträgen:
///
///   1. Ein Ordner außerhalb des Papierkorbs wandert samt Inhalt hinein.
///      Nichts geht verloren, alles bleibt sichtbar.
///   2. Ein Ordner, der schon drin liegt, wird endgültig entfernt — mit
///      Löschvermerk, damit ein Abgleich ihn nicht zurückbringt.
#[tauri::command]
pub fn vault_remove_folder(state: tauri::State<'_, Vault>, path: String) -> Result<bool, String> {
    let mut vault = lock(&state)?;
    let db = vault.database_mut()?;

    let Some(group) = resolve_editable(db, &path)? else { return Ok(false) };

    if is_recycled(db, group) {
        db.group_mut(group)
            .ok_or("Ordner verschwunden.")?
            .track_changes()
            .remove()
            .map_err(|_| "Die Wurzel lässt sich nicht löschen.".to_string())?;
        return Ok(true);
    }

    let bin = ensure_recycle_bin(db);
    db.group_mut(group)
        .ok_or("Ordner verschwunden.")?
        .move_to(bin)
        .map_err(|e| format!("Verschieben in den Papierkorb fehlgeschlagen: {e}"))?;
    Ok(true)
}

/// Übernimmt den Elternordner des Bezugsordners. Siehe Modulkommentar.
#[tauri::command]
pub fn vault_reorder_folder(
    state: tauri::State<'_, Vault>,
    path: String,
    reference_path: String,
    _position: String,
) -> Result<bool, String> {
    let parent = reference_path
        .rsplit_once('/')
        .map(|(head, _)| head.to_string())
        .unwrap_or_else(|| ROOT_LABEL.to_string());

    vault_move_folder(state, path, parent)
}

/* =========================================================
   Helfer
   ========================================================= */

/// Sucht die Gruppe zum Pfad und weist die Wurzel zurück — die lässt sich
/// weder umbenennen noch verschieben noch löschen.
fn resolve_editable(db: &keepass::Database, path: &str) -> Result<Option<GroupId>, String> {
    let Some(group) = find_group(db, path) else { return Ok(None) };

    if group == db.root().id() {
        return Err(format!("„{ROOT_LABEL}“ ist die Wurzel und lässt sich nicht ändern."));
    }
    Ok(Some(group))
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepass::db::Value;
    use keepass::Database;

    /// Ein Eintrag mit einem Anhang „alt.txt", dazu der Tresor drumherum.
    fn tresor_mit_anhang() -> (crate::state::VaultState, EntryId, usize) {
        let mut db = Database::new();
        let id = db.root_mut().add_entry().id();
        let anhang = db
            .entry_mut(id)
            .unwrap()
            .add_attachment("alt.txt", Value::Unprotected(b"Inhalt".to_vec()))
            .id()
            .id();

        let mut vault = crate::state::VaultState::default();
        vault.db = Some(db);
        (vault, id, anhang)
    }

    fn eintrag(anhaenge: serde_json::Value) -> dto::Entry {
        serde_json::from_value(serde_json::json!({ "attachments": anhaenge })).unwrap()
    }

    fn anhaenge(vault: &crate::state::VaultState, id: EntryId) -> Vec<(String, Vec<u8>)> {
        let db = vault.database().unwrap();
        let mut liste: Vec<_> = db
            .entry(id)
            .unwrap()
            .attachments_named()
            .map(|(name, att)| (name.to_string(), att.data.get().to_vec()))
            .collect();
        liste.sort();
        liste
    }

    #[test]
    fn umbenennen_behaelt_den_inhalt() {
        let (mut vault, id, anhang) = tresor_mit_anhang();

        let neu = eintrag(serde_json::json!([{ "name": "neu.md", "ref": anhang.to_string() }]));
        apply_attachments(&mut vault, id, &neu).unwrap();

        assert_eq!(anhaenge(&vault, id), vec![("neu.md".to_string(), b"Inhalt".to_vec())]);
    }

    #[test]
    fn bearbeiten_ersetzt_den_inhalt() {
        let (mut vault, id, _) = tresor_mit_anhang();
        vault.staged.insert(
            "staged:1".into(),
            crate::state::StagedAttachment { name: "alt.txt".into(), bytes: b"Neu".to_vec() },
        );

        let neu = eintrag(serde_json::json!([{ "name": "alt.txt", "ref": "staged:1" }]));
        apply_attachments(&mut vault, id, &neu).unwrap();

        assert_eq!(anhaenge(&vault, id), vec![("alt.txt".to_string(), b"Neu".to_vec())]);
    }

    /// Speichern und neu öffnen — so, wie es die Datei auf der Platte sieht.
    fn neu_geladen(vault: &crate::state::VaultState, id: EntryId) -> Vec<(String, Vec<u8>)> {
        use keepass::DatabaseKey;

        let mut bytes = Vec::new();
        vault.database().unwrap().save(&mut bytes, DatabaseKey::new().with_password("test")).unwrap();
        let db = Database::parse(&bytes, DatabaseKey::new().with_password("test")).unwrap();

        let uuid = vault.database().unwrap().entry(id).unwrap().id().uuid();
        let entry = db.iter_all_entries().find(|e| e.id().uuid() == uuid).unwrap();
        let mut liste: Vec<_> = entry
            .attachments_named()
            .map(|(name, att)| (name.to_string(), att.data.get().to_vec()))
            .collect();
        liste.sort();
        liste
    }

    #[test]
    fn bearbeiteter_anhang_ueberlebt_das_speichern() {
        let (mut vault, id, _) = tresor_mit_anhang();

        // Ein zweiter Anhang, damit die Kennungen nach dem Ersetzen Lücken haben.
        let zweiter = vault
            .database_mut()
            .unwrap()
            .entry_mut(id)
            .unwrap()
            .add_attachment("zwei.txt", Value::Unprotected(b"Zwei".to_vec()))
            .id()
            .id();

        vault.staged.insert(
            "staged:1".into(),
            crate::state::StagedAttachment { name: "alt.txt".into(), bytes: b"Neu".to_vec() },
        );
        let neu = eintrag(serde_json::json!([
            { "name": "alt.txt", "ref": "staged:1" },
            { "name": "zwei.txt", "ref": zweiter.to_string() }
        ]));
        apply_attachments(&mut vault, id, &neu).unwrap();

        assert_eq!(
            neu_geladen(&vault, id),
            vec![
                ("alt.txt".to_string(), b"Neu".to_vec()),
                ("zwei.txt".to_string(), b"Zwei".to_vec()),
            ]
        );
    }

    #[test]
    fn einzelner_anhang_wird_sofort_geschrieben() {
        let (mut vault, id, anhang) = tresor_mit_anhang();
        let uuid = vault.database().unwrap().entry(id).unwrap().id().uuid().to_string();

        // Umbenennen ohne neuen Inhalt …
        write_attachment(&mut vault, &uuid, "neu.md", &anhang.to_string(), Some("alt.txt")).unwrap();
        assert_eq!(anhaenge(&vault, id), vec![("neu.md".to_string(), b"Inhalt".to_vec())]);

        // … dann neuer Inhalt unter demselben Namen.
        vault.staged.insert(
            "staged:9".into(),
            crate::state::StagedAttachment { name: "neu.md".into(), bytes: b"Bearbeitet".to_vec() },
        );
        write_attachment(&mut vault, &uuid, "neu.md", "staged:9", Some("neu.md")).unwrap();
        assert_eq!(neu_geladen(&vault, id), vec![("neu.md".to_string(), b"Bearbeitet".to_vec())]);

        // Ein vergebener Name wird abgelehnt.
        vault.staged.insert(
            "staged:10".into(),
            crate::state::StagedAttachment { name: "neu.md".into(), bytes: b"x".to_vec() },
        );
        assert!(write_attachment(&mut vault, &uuid, "neu.md", "staged:10", None).is_err());
    }

    #[test]
    fn unveraendert_bleibt_unveraendert() {
        let (mut vault, id, anhang) = tresor_mit_anhang();

        let gleich = eintrag(serde_json::json!([{ "name": "alt.txt", "ref": anhang.to_string() }]));
        apply_attachments(&mut vault, id, &gleich).unwrap();

        assert_eq!(anhaenge(&vault, id), vec![("alt.txt".to_string(), b"Inhalt".to_vec())]);
    }
}

/// Vermerkt, dass Einträge gerade benutzt wurden (`LastAccessTime`).
///
/// Daraus entsteht im Sicherheitscheck die Liste der inaktiven Einträge —
/// und KeePassXC zeigt denselben Zeitpunkt an. Geschrieben wird er mit dem
/// nächsten Speichern; nur bei `persist` sofort, etwa wenn der Nutzer
/// ausdrücklich „wird noch genutzt" sagt.
#[tauri::command]
pub fn vault_mark_accessed(
    app: tauri::AppHandle,
    state: tauri::State<'_, Vault>,
    ids: Vec<String>,
    persist: Option<bool>,
) -> Result<usize, String> {
    let zahl = {
        let mut vault = state.lock().map_err(|_| "Kern blockiert.".to_string())?;
        mark_accessed(&mut vault, &ids)?
    };
    if persist.unwrap_or(false) && zahl > 0 {
        crate::database::commit(&app, &state)?;
    }
    Ok(zahl)
}

pub fn mark_accessed(vault: &mut crate::state::VaultState, ids: &[String]) -> Result<usize, String> {
    let db = vault.database_mut()?;
    let treffer: Vec<_> = db
        .iter_all_entries()
        .filter(|e| ids.iter().any(|id| *id == e.id().uuid().to_string()))
        .map(|e| e.id())
        .collect();
    let jetzt = keepass::db::Times::now();
    for id in &treffer {
        if let Some(mut entry) = db.entry_mut(*id) {
            entry.times.last_access = Some(jetzt);
        }
    }
    Ok(treffer.len())
}
