//! Der Zustand des Kerns und die Umrechnung zwischen Gruppenbaum und
//! Ordnerpfad.
//!
//! Die Oberfläche kennt Ordner nur als Pfad (`"Arbeit/KoG"`), KDBX kennt
//! einen Baum aus Gruppen. Übersetzt wird hier, an genau einer Stelle.
//!
//! Die Wurzelgruppe hat in KDBX einen Namen (meist „Root" oder der
//! Datenbankname), der die Oberfläche nichts angeht. Einträge, die direkt
//! darin liegen, bekommen deshalb den Pfad `"Allgemein"`.

use std::collections::HashMap;
use std::path::PathBuf;

use keepass::db::GroupId;
use keepass::Database;
use zeroize::Zeroizing;

/// Wie die Wurzelgruppe in der Oberfläche heißt.
pub const ROOT_LABEL: &str = "Allgemein";

#[derive(Default)]
pub struct VaultState {
    pub db: Option<Database>,
    pub path: Option<PathBuf>,

    /// SHA-256 der Datei, wie sie beim Öffnen auf der Platte lag. Vor dem
    /// Schreiben wird erneut gehasht — hat inzwischen KeePassXC oder die
    /// Nextcloud-Synchronisierung zugeschlagen, wird nicht überschrieben.
    pub opened_hash: Option<[u8; 32]>,

    /// Nur KDBX 4.1 lässt sich zurückschreiben. Alles andere wird geöffnet,
    /// aber `vault_commit` verweigert die Arbeit.
    pub read_only: bool,

    /// Wann zuletzt etwas über die Schnittstelle kam — für die Selbstsperre.
    pub last_activity: Option<std::time::Instant>,
    pub auto_lock_minutes: u64,

    /// Das Master-Passwort — gebraucht, um beim Speichern wieder zu
    /// verschlüsseln. Verlässt den Kern nie.
    pub master: Option<Zeroizing<String>>,

    /// Klartextwerte, adressiert über ihren Token.
    pub secrets: HashMap<String, Zeroizing<String>>,

    /// (Eintrags-UUID, Feldname) → Token. Sorgt dafür, dass ein Feld über
    /// mehrere `vault_list_entries` hinweg denselben Token behält.
    pub field_tokens: HashMap<(String, String), String>,

    /// Angehängte Dateien, die noch zu keinem Eintrag gehören.
    ///
    /// In KDBX hängt ein Anhang immer an einem Eintrag; einen freistehenden
    /// gibt es nicht. Die Oberfläche wählt ihn aber aus, **bevor** der
    /// Eintrag gespeichert wird. Deshalb liest der Kern die Datei sofort ein
    /// und legt sie hier ab; `vault_save_entry` löst die Verweise auf.
    ///
    /// Verworfen wird beim Sperren — wer den Dialog abbricht, lässt höchstens
    /// ein paar Bytes bis dahin liegen.
    pub staged: HashMap<String, StagedAttachment>,

    next_token: u32,
}

/// Eine eingelesene Datei, die auf ihren Eintrag wartet.
pub struct StagedAttachment {
    pub name: String,
    pub bytes: Vec<u8>,
}

impl VaultState {
    /// Vergibt einen neuen, noch unbenutzten Token.
    pub fn new_token(&mut self) -> String {
        self.next_token += 1;
        format!("s{}", self.next_token)
    }

    /// Der Token eines Feldes — vorhandener oder frisch vergebener.
    pub fn token_for(&mut self, uuid: &str, field: &str) -> String {
        let key = (uuid.to_string(), field.to_string());
        if let Some(token) = self.field_tokens.get(&key) {
            return token.clone();
        }
        let token = self.new_token();
        self.field_tokens.insert(key, token.clone());
        token
    }

    pub fn database(&self) -> Result<&Database, String> {
        self.db.as_ref().ok_or_else(|| "Keine Datenbank geöffnet.".into())
    }

    pub fn database_mut(&mut self) -> Result<&mut Database, String> {
        self.db.as_mut().ok_or_else(|| "Keine Datenbank geöffnet.".into())
    }

    /// Merkt sich, dass gerade etwas passiert ist — schiebt die Selbstsperre
    /// nach hinten.
    pub fn touch(&mut self) {
        if self.db.is_some() {
            self.last_activity = Some(std::time::Instant::now());
        }
    }

    /// Ist die Ruhezeit abgelaufen?
    pub fn idle_expired(&self) -> bool {
        if self.db.is_none() || self.auto_lock_minutes == 0 {
            return false;
        }
        self.last_activity
            .is_some_and(|at| at.elapsed().as_secs() >= self.auto_lock_minutes * 60)
    }

    /// Räumt alles aus dem Speicher. `Zeroizing` überschreibt die Werte dabei.
    pub fn clear(&mut self) {
        self.db = None;
        self.path = None;
        self.master = None;
        self.opened_hash = None;
        self.read_only = false;
        self.last_activity = None;
        self.secrets.clear();
        self.field_tokens.clear();
        self.staged.clear();
        self.next_token = 0;
    }
}

/* =========================================================
   Papierkorb
   ========================================================= */

/// Voreingestellter Name, falls die Datenbank noch keinen Papierkorb hat.
pub const RECYCLE_BIN_NAME: &str = "Papierkorb";

/// Die Gruppe, die KDBX als Papierkorb führt — falls es eine gibt.
pub fn recycle_bin(db: &Database) -> Option<GroupId> {
    db.recycle_bin().map(|g| g.id())
}

/// Legt den Papierkorb an, wenn nötig, und trägt ihn in die Meta-Daten ein.
pub fn ensure_recycle_bin(db: &mut Database) -> GroupId {
    if let Some(id) = recycle_bin(db) {
        return id;
    }

    let root = db.root().id();
    let id = add_child(db, root, RECYCLE_BIN_NAME);

    db.meta.recyclebin_uuid = Some(id.uuid());
    db.meta.recyclebin_enabled = Some(true);
    db.meta.recyclebin_changed = Some(keepass::db::Times::now());
    id
}

/// Liegt `group` im Papierkorb — oder ist es der Papierkorb selbst?
pub fn is_recycled(db: &Database, group: GroupId) -> bool {
    let Some(bin) = recycle_bin(db) else { return false };

    let mut current = Some(group);
    while let Some(id) = current {
        if id == bin {
            return true;
        }
        current = db.group(id).and_then(|g| g.parent().map(|p| p.id()));
    }
    false
}

/* =========================================================
   Gruppenbaum ↔ Ordnerpfad
   ========================================================= */

/// Der Pfad einer Gruppe, wie die Oberfläche ihn erwartet.
pub fn folder_path(db: &Database, id: GroupId) -> String {
    let root = db.root().id();
    let mut parts: Vec<String> = Vec::new();
    let mut current = Some(id);

    while let Some(gid) = current {
        if gid == root {
            break;
        }
        let Some(group) = db.group(gid) else { break };
        parts.push(group.name.clone());
        current = group.parent().map(|p| p.id());
    }

    parts.reverse();
    if parts.is_empty() { ROOT_LABEL.to_string() } else { parts.join("/") }
}

/// Alle Ordner der Datenbank, die Wurzel eingeschlossen.
pub fn all_folders(db: &Database) -> Vec<String> {
    let root = db.root().id();
    let mut out = vec![ROOT_LABEL.to_string()];

    for group in db.iter_all_groups() {
        if group.id() != root {
            out.push(folder_path(db, group.id()));
        }
    }
    out
}

/// Sucht die Gruppe zu einem Pfad, ohne etwas anzulegen.
pub fn find_group(db: &Database, path: &str) -> Option<GroupId> {
    let mut current = db.root().id();

    if path.is_empty() || path == ROOT_LABEL {
        return Some(current);
    }

    // Über die Kennung laufen und nicht über `GroupRef`: Letzteres liehe sich
    // bei jedem Schritt selbst aus.
    for part in path.split('/').filter(|p| !p.is_empty()) {
        current = db.group(current)?.groups().find(|g| g.name == part)?.id();
    }
    Some(current)
}

/// Wie `find_group`, legt fehlende Ebenen aber an.
pub fn ensure_group(db: &mut Database, path: &str) -> GroupId {
    let mut current = db.root().id();

    if path.is_empty() || path == ROOT_LABEL {
        return current;
    }

    for part in path.split('/').filter(|p| !p.is_empty()) {
        let existing = db
            .group(current)
            .and_then(|g| g.groups().find(|c| c.name == part).map(|c| c.id()));

        current = match existing {
            Some(id) => id,
            None => add_child(db, current, part),
        };
    }
    current
}

/// Eigene Funktion, damit die Ausleihe von `db` endet, bevor das Ergebnis
/// zugewiesen wird.
fn add_child(db: &mut Database, parent: GroupId, name: &str) -> GroupId {
    #[allow(clippy::expect_used)]
    let mut group = db.group_mut(parent).expect("Elterngruppe existiert");
    let mut child = group.add_group();
    child.name = name.to_string();
    child.id()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Baut einen kleinen Baum: Wurzel → Arbeit → KoG
    fn baum() -> (Database, GroupId, GroupId) {
        let mut db = Database::new();
        let arbeit = ensure_group(&mut db, "Arbeit");
        let kog = ensure_group(&mut db, "Arbeit/KoG");
        (db, arbeit, kog)
    }

    #[test]
    fn pfad_und_zurueck() {
        let (db, arbeit, kog) = baum();

        assert_eq!(folder_path(&db, arbeit), "Arbeit");
        assert_eq!(folder_path(&db, kog), "Arbeit/KoG");
        assert_eq!(folder_path(&db, db.root().id()), ROOT_LABEL);

        assert_eq!(find_group(&db, "Arbeit/KoG"), Some(kog));
        assert_eq!(find_group(&db, ROOT_LABEL), Some(db.root().id()));
        assert_eq!(find_group(&db, "Gibtsnicht"), None);
    }

    #[test]
    fn ensure_group_legt_nur_fehlendes_an() {
        let (mut db, _, kog) = baum();

        // Zweiter Aufruf darf keine zweite Gruppe erzeugen.
        assert_eq!(ensure_group(&mut db, "Arbeit/KoG"), kog);

        let vorher = db.iter_all_groups().count();
        ensure_group(&mut db, "Arbeit");
        assert_eq!(db.iter_all_groups().count(), vorher);
    }

    #[test]
    fn alle_ordner_enthalten_die_wurzel() {
        let (db, _, _) = baum();
        let mut ordner = all_folders(&db);
        ordner.sort();

        assert_eq!(ordner, vec!["Allgemein", "Arbeit", "Arbeit/KoG"]);
    }

    #[test]
    fn papierkorb_erkennt_untergruppen() {
        let mut db = Database::new();
        let bin = ensure_recycle_bin(&mut db);
        let drin = ensure_group(&mut db, &format!("{RECYCLE_BIN_NAME}/Alt"));
        let draussen = ensure_group(&mut db, "Arbeit");

        assert!(is_recycled(&db, bin));
        assert!(is_recycled(&db, drin));
        assert!(!is_recycled(&db, draussen));
        assert!(!is_recycled(&db, db.root().id()));
    }

    #[test]
    fn papierkorb_wird_nur_einmal_angelegt() {
        let mut db = Database::new();
        let erster = ensure_recycle_bin(&mut db);
        assert_eq!(ensure_recycle_bin(&mut db), erster);
        assert_eq!(recycle_bin(&db), Some(erster));
    }
}
