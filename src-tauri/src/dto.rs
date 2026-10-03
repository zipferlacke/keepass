//! Die Typen, die über die IPC-Grenze gehen.
//!
//! Alles hier ist `camelCase`, weil es auf der anderen Seite JavaScript ist.
//! Maßgeblich für die Form ist `ui/config/demo.json` — was dort steht, muss
//! hier herauskommen.
//!
//! Ein Eintrag trägt **kein** Passwortfeld. Geschützte Werte erscheinen nur
//! als Token (`passwordToken`, `totpToken`); den Wert dazu kennt allein der
//! Kern.

use serde::{Deserialize, Serialize};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseInfo {
    pub name: String,
    pub path: String,
    /// Zurückschreiben kann die Bibliothek nur KDBX 4.1. Ältere Dateien
    /// werden geöffnet, aber nicht gespeichert.
    pub read_only: bool,
    /// Fassung des Containers, für die Anzeige — z. B. `"KDBX 4.1"`.
    pub format: String,
    /// Nur gesetzt, wenn die Datei nicht lesbar war und stattdessen die
    /// Offline-Kopie geöffnet wurde: wann die Kopie entstand.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cached_at: Option<String>,
    /// Warum die Datei selbst nicht ging.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offline_reason: Option<String>,
}

/// Wie die offene Datenbank heißt und wie stark sie verschlüsselt ist.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Security {
    /// Der Name aus der Datei — nicht der Dateiname.
    pub name: String,
    /// `"KDBX 4.1"`
    pub format: String,
    pub read_only: bool,
    /// Welches Verfahren den Schlüssel aus dem Passwort ableitet.
    pub kdf: String,
    pub iterations: u64,
    pub memory_mib: u64,
    pub parallelism: u32,
    /// Womit der Container verschlüsselt ist, etwa `"AES-256"`.
    pub cipher: String,
    /// Welche der drei Stufen das ist — oder `"eigen"`.
    pub level: String,
}

/// Welche Wege zum Entsperren stehen auf diesem Gerät bereit?
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockMethods {
    /// Immer wahr — das Master-Passwort geht überall.
    pub password: bool,
    /// Es liegt ein mit PIN versiegeltes Master-Passwort vor.
    pub pin: bool,
    /// Fingerabdruck ist hinterlegt **und** die Plattform kann prüfen.
    /// Diese Datenbank ist für den Fingerabdruck freigeschaltet **und** das
    /// Gerät kann ihn prüfen.
    pub biometric: bool,
    /// Kann das Gerät überhaupt biometrisch prüfen? Das ist die andere
    /// Frage — sie entscheidet, ob die Einstellung angeboten wird.
    pub biometric_available: bool,
    /// Es ist überhaupt eine App-PIN festgelegt. Ohne sie lässt sich keine
    /// Datenbank freischalten.
    pub pin_set: bool,
    /// Ein Systemschlüsselbund ist erreichbar. Ohne ihn ist die
    /// Schnellentsperrung nur so stark wie die PIN allein — die
    /// Oberfläche soll das sagen dürfen.
    pub keyring: bool,
    /// Diese Datenbank ist gerätegebunden freigeschaltet (Windows Hello)
    /// und das Gerät kann es gerade einlösen. Dann ersetzt dieser Weg PIN
    /// und Master-Passwort.
    pub device: bool,
    /// Das Gerät kann einen an die Biometrie gebundenen Schlüssel liefern —
    /// unabhängig davon, ob schon etwas freigeschaltet ist.
    pub device_available: bool,
    /// Wie der Weg heißt, etwa `"Windows Hello"`.
    pub device_label: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TotpConfig {
    #[serde(default = "default_digits")]
    pub digits: u32,
    #[serde(default = "default_period")]
    pub period: u64,
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
    /// Für welchen Zeitpunkt der Code gilt, in Millisekunden seit 1970.
    ///
    /// Ohne Angabe: jetzt. Die Vorschau „als Nächstes …" fragt damit den
    /// Code des folgenden Zeitfensters ab — ohne ihn rechnete der Kern
    /// wieder den aktuellen, und es stand zweimal dasselbe da.
    #[serde(default)]
    pub at: Option<u64>,
}

fn default_digits() -> u32 { 6 }
fn default_period() -> u64 { 30 }
fn default_algorithm() -> String { "SHA1".into() }

impl Default for TotpConfig {
    fn default() -> Self {
        Self { digits: default_digits(), period: default_period(), algorithm: default_algorithm(), at: None }
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentLink {
    pub name: String,
    #[serde(rename = "ref")]
    pub reference: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    /// Fehlt beim Anlegen — dann vergibt der Kern eine.
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub folder: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub modified: String,
    /// Letzter Zugriff laut Datei — gesetzt auch von KeePassXC und Co.
    #[serde(default)]
    pub accessed: String,

    #[serde(default)]
    pub has_password: bool,
    #[serde(default)]
    pub password_token: Option<String>,
    #[serde(default)]
    pub has_totp: bool,
    #[serde(default)]
    pub totp_token: Option<String>,
    #[serde(default)]
    pub totp_config: TotpConfig,

    #[serde(default)]
    pub passkey: bool,
    /// Für welche Seite der Passkey gilt und für welches Konto — nur zur
    /// Anzeige, geändert wird ein Passkey nie über den Dialog.
    #[serde(default)]
    pub passkey_site: Option<String>,
    #[serde(default)]
    pub passkey_user: Option<String>,
    /// Das Website-Icon aus der Datenbank als `data:`-Adresse (favicon.rs).
    /// Nur zur Anzeige; gesetzt wird es nie über den Dialog.
    #[serde(default, skip_deserializing)]
    pub icon: Option<String>,
    /// `YYYY-MM-DD` oder nichts.
    #[serde(default)]
    pub expires: Option<String>,
    #[serde(default)]
    pub attachments: Vec<AttachmentLink>,

    /// Liegt im Papierkorb. Der Eintrag wird weiterhin angezeigt — mit
    /// Passwort und allem — zählt aber beim Sicherheitscheck nicht mit.
    #[serde(default)]
    pub recycled: bool,
    /// Seit wann er im Papierkorb liegt — nach `PAPIERKORB_TAGE` ist er weg.
    #[serde(default, skip_deserializing)]
    pub recycled_since: Option<String>,
}

/// Ein eingelesener Anhang, der noch auf seinen Eintrag wartet.
///
/// Nur die Angaben zur Anzeige — der Inhalt bleibt im Kern und wird über
/// `ref` angesprochen.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StagedAttachment {
    pub name: String,
    #[serde(rename = "type")]
    pub mime: String,
    pub size: u64,
    #[serde(rename = "ref")]
    pub reference: String,
}

/// Ein Anhang, wie ihn die Vorschau erwartet: Inhalt als Data-URL.
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Attachment {
    pub name: String,
    #[serde(rename = "type")]
    pub mime: String,
    pub data: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HashPrefix {
    pub prefix: String,
    pub suffix: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Strength {
    pub score: u8,
    pub entropy: u32,
    pub label: String,
    pub hints: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpResult {
    pub code: String,
    pub remaining: u64,
}

/// Wunsch, eine Datenbank für die Schnellentsperrung freizuschalten.
///
/// Die PIN gilt fürs ganze Programm; `allow_pin` und `allow_biometric`
/// entscheiden pro Datenbank, ob sie damit aufgehen darf.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Remember {
    /// Nur für PIN und Fingerabdruck nötig, nicht für den Geräteschlüssel.
    #[serde(default)]
    pub pin: String,
    #[serde(default)]
    pub allow_pin: bool,
    #[serde(default)]
    pub allow_biometric: bool,
    /// Gerätegebunden freischalten (Windows Hello) — braucht keine PIN.
    #[serde(default)]
    pub allow_device: bool,
}

/* =========================================================
   Versionen
   ========================================================= */

/// Ein aufgehobener Stand der Datenbank.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Version {
    /// Dateiname ohne Endung — so wird der Stand wieder angefordert.
    pub id: String,
    /// Wann er abgelegt wurde (RFC 3339).
    pub at: String,
    /// Weshalb: „Geöffnet", „Gespeichert", „Von einem anderen Gerät".
    pub reason: String,
    pub size: u64,
}

/// Ein Eintrag, der sich seit einem Stand geändert hat.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionChange {
    pub id: String,
    pub name: String,
    pub folder: String,
    /// `neu`, `geloescht` oder `geaendert`.
    pub kind: String,
    pub fields: Vec<VersionField>,
}

/// Ein einzelnes geändertes Feld. Bei Geheimnissen bleiben die Werte leer —
/// die Oberfläche braucht nur zu wissen, **dass** sich etwas geändert hat.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionField {
    pub name: String,
    pub before: Option<String>,
    pub after: Option<String>,
}
