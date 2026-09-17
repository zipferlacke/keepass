//! Geheimnisse verwahren und auswerten.
//!
//! Ein Wert verlässt den Kern auf genau zwei Wegen: `vault_reveal_secret`
//! auf ausdrückliche Anforderung, und `vault_copy_secret` — das gibt ihn
//! gar nicht heraus, sondern legt ihn direkt in die Zwischenablage.
//!
//! Alles andere rechnet hier und gibt nur das Ergebnis zurück: Stärke,
//! SHA-1-Präfix für den k-Anonymity-Abgleich, Mehrfachverwendung, TOTP.

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use sha1::{Digest, Sha1};
use tauri_plugin_clipboard_manager::ClipboardExt;
use zeroize::Zeroizing;

use crate::dto;
use crate::state::VaultState;
use crate::Vault;

fn lock<'a>(state: &tauri::State<'a, Vault>) -> Result<std::sync::MutexGuard<'a, VaultState>, String> {
    let mut vault = state.inner().lock().map_err(|_| "Kern blockiert.".to_string())?;
    vault.touch();
    Ok(vault)
}

fn value_of(vault: &VaultState, token: &str) -> Result<String, String> {
    vault.secrets.get(token).map(|v| v.to_string()).ok_or_else(|| "Unbekannter Verweis.".into())
}

/// Sperren und den Wert holen. Eigene Funktion, weil `&lock(…)?` die
/// Umwandlung von `MutexGuard` nach `&VaultState` nicht durchreicht.
fn take(state: &tauri::State<'_, Vault>, token: &str) -> Result<String, String> {
    let vault = lock(state)?;
    value_of(&vault, token)
}

/* =========================================================
   Verwalten
   ========================================================= */

#[tauri::command]
pub fn vault_new_secret(state: tauri::State<'_, Vault>, value: String) -> Result<String, String> {
    let mut vault = lock(&state)?;
    let token = vault.new_token();
    vault.secrets.insert(token.clone(), Zeroizing::new(value));
    Ok(token)
}

#[tauri::command]
pub fn vault_set_secret(
    state: tauri::State<'_, Vault>,
    token: String,
    value: String,
) -> Result<bool, String> {
    lock(&state)?.secrets.insert(token, Zeroizing::new(value));
    Ok(true)
}

#[tauri::command]
pub fn vault_drop_secret(state: tauri::State<'_, Vault>, token: String) -> Result<bool, String> {
    let mut vault = lock(&state)?;
    vault.secrets.remove(&token);
    vault.field_tokens.retain(|_, t| t != &token);
    Ok(true)
}

#[tauri::command]
pub fn vault_reveal_secret(
    state: tauri::State<'_, Vault>,
    token: String,
) -> Result<String, String> {
    take(&state, &token)
}

/// Legt einen Wert in die Zwischenablage, ohne ihn der Oberfläche zu zeigen.
#[tauri::command]
pub fn vault_copy_secret(
    app: tauri::AppHandle,
    state: tauri::State<'_, Vault>,
    token: String,
) -> Result<bool, String> {
    let value = take(&state, &token)?;
    app.clipboard()
        .write_text(value)
        .map_err(|e| format!("Zwischenablage nicht erreichbar: {e}"))?;
    Ok(true)
}

/* =========================================================
   Auswertungen
   ========================================================= */

/// SHA-1 in Präfix und Suffix geteilt. Nach außen geht davon nur das
/// fünfstellige Präfix — den Rest vergleicht die Oberfläche selbst.
#[tauri::command]
pub fn vault_hash_prefix(
    state: tauri::State<'_, Vault>,
    token: String,
) -> Result<dto::HashPrefix, String> {
    let value = take(&state, &token)?;

    let digest = Sha1::digest(value.as_bytes());
    let hex = digest.iter().map(|b| format!("{b:02X}")).collect::<String>();

    Ok(dto::HashPrefix { prefix: hex[..5].to_string(), suffix: hex[5..].to_string() })
}

/// Gruppen gleicher Passwörter — nur Token, keine Werte.
#[tauri::command]
pub fn vault_duplicate_groups(state: tauri::State<'_, Vault>) -> Result<Vec<Vec<String>>, String> {
    let vault = lock(&state)?;

    let mut by_value: HashMap<&str, Vec<String>> = HashMap::new();
    for (token, value) in &vault.secrets {
        by_value.entry(value.as_str()).or_default().push(token.clone());
    }

    Ok(by_value.into_values().filter(|g| g.len() > 1).collect())
}

#[tauri::command]
pub fn vault_totp(
    state: tauri::State<'_, Vault>,
    token: String,
    config: dto::TotpConfig,
) -> Result<dto::TotpResult, String> {
    let raw = take(&state, &token)?;

    // Steht schon eine vollständige otpauth-Adresse im Feld, gelten deren
    // Angaben — sie kommen von der Gegenstelle. Sonst bauen wir eine aus dem
    // Base32-Geheimnis und den Einstellungen des Eintrags.
    let uri = if raw.starts_with("otpauth://") {
        raw
    } else {
        format!(
            "otpauth://totp/WKeePass?secret={}&digits={}&period={}&algorithm={}",
            raw.trim().replace(' ', ""),
            config.digits,
            config.period,
            config.algorithm
        )
    };

    let totp: keepass::db::TOTP = uri.parse().map_err(|e| format!("TOTP nicht lesbar: {e}"))?;
    let code = totp.value_now().map_err(|e| format!("Systemzeit unbrauchbar: {e}"))?;

    Ok(dto::TotpResult { code: code.code.clone(), remaining: code.valid_for.as_secs() })
}

/* =========================================================
   Anhänge
   ========================================================= */

#[tauri::command]
pub fn vault_attachment(
    state: tauri::State<'_, Vault>,
    r#ref: String,
) -> Result<Option<dto::Attachment>, String> {
    let vault = lock(&state)?;

    // Ein noch nicht gespeicherter Anhang liegt im Zwischenspeicher — die
    // Vorschau im Dialog soll ihn trotzdem zeigen können.
    if let Some(staged) = vault.staged.get(&r#ref) {
        let mime = mime_from_name(&staged.name);
        return Ok(Some(dto::Attachment {
            name: staged.name.clone(),
            data: format!("data:{mime};base64,{}", B64.encode(&staged.bytes)),
            mime,
        }));
    }

    let db = vault.database()?;

    let Ok(wanted) = r#ref.parse::<usize>() else { return Ok(None) };

    let Some(attachment) = db.iter_all_attachments().find(|a| a.id().id() == wanted) else {
        return Ok(None);
    };

    // Den Namen trägt nicht der Anhang, sondern der Eintrag, der ihn nutzt.
    let name = db
        .iter_all_entries()
        .find_map(|e| {
            e.attachments_named()
                .find(|(_, a)| a.id().id() == wanted)
                .map(|(name, _)| name.to_string())
        })
        .unwrap_or_else(|| format!("Anhang {wanted}"));

    let bytes = attachment.data.get();
    let mime = mime_from_name(&name);

    Ok(Some(dto::Attachment {
        name,
        data: format!("data:{mime};base64,{}", B64.encode(bytes)),
        mime,
    }))
}

/// Kennzeichnet einen Anhang, der noch nicht in der Datenbank steht.
pub const STAGED_PREFIX: &str = "staged:";

/// Schreibt einen Anhang als Datei auf die Platte.
///
/// Ein `<a download>` im Webview führt hier zu nichts: WebKitGTK bringt in
/// einem eingebetteten View keine Download-Behandlung mit, der Klick
/// verpufft folgenlos. Deshalb macht es der Kern — Speichern-Dialog des
/// Systems, Bytes direkt aus der Datenbank, fertig.
///
/// Zurück kommt der Pfad, oder nichts, wenn abgebrochen wurde.
#[tauri::command]
pub async fn save_attachment(
    app: tauri::AppHandle,
    state: tauri::State<'_, Vault>,
    r#ref: String,
) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;

    // Erst holen, dann fragen: Ist der Anhang weg, soll kein Dialog aufgehen.
    let (name, bytes) = {
        let vault = lock(&state)?;

        if let Some(staged) = vault.staged.get(&r#ref) {
            (staged.name.clone(), staged.bytes.clone())
        } else {
            let db = vault.database()?;
            let wanted: usize = r#ref.parse().map_err(|_| "Unbekannter Anhang.")?;

            let attachment = db
                .iter_all_attachments()
                .find(|a| a.id().id() == wanted)
                .ok_or("Der Anhang steht nicht mehr in der Datenbank.")?;

            // Den Namen trägt der Eintrag, nicht der Anhang.
            let name = db
                .iter_all_entries()
                .find_map(|e| {
                    e.attachments_named()
                        .find(|(_, a)| a.id().id() == wanted)
                        .map(|(name, _)| name.to_string())
                })
                .unwrap_or_else(|| format!("Anhang {wanted}"));

            (name, attachment.data.get().to_vec())
        }
    };

    let (tx, rx) = std::sync::mpsc::channel();
    app.dialog().file().set_file_name(&name).save_file(move |path| {
        let _ = tx.send(path);
    });

    let Some(target) = rx.recv().map_err(|e| format!("Speichern abgebrochen: {e}"))? else {
        return Ok(None);
    };

    let target = target.into_path().map_err(|e| format!("Pfad nicht nutzbar: {e}"))?;
    std::fs::write(&target, &bytes).map_err(|e| format!("Schreiben fehlgeschlagen: {e}"))?;

    Ok(Some(target.to_string_lossy().to_string()))
}

/// Wie groß ein einzelner Anhang höchstens sein darf.
///
/// Eine KDBX-Datei wird beim Speichern vollständig neu verschlüsselt und
/// geschrieben. Große Anhänge machen also jedes Speichern langsam — und die
/// Datei wandert oft durch eine Synchronisierung.
const MAX_ATTACHMENT_BYTES: u64 = 2 * 1024 * 1024;

/// Wählt Dateien über den Dialog des Betriebssystems und liest sie ein.
///
/// Der Weg über den Kern statt über ein `<input type="file">` hat zwei
/// Gründe. Erstens landen die Bytes damit nie im Webview — dieselbe
/// Aufgabenteilung wie bei den Geheimnissen. Zweitens ist es derselbe
/// Dialog wie beim Öffnen einer Datenbank, also auch derselbe
/// Zugriffsrahmen; ein Webview-Dateifeld hängt dagegen an den Freigaben des
/// Browsers.
///
/// Zurück kommen nur die Angaben zur Anzeige. Der Inhalt bleibt im Kern und
/// wird über `ref` angesprochen.
#[tauri::command]
pub async fn pick_attachments(
    app: tauri::AppHandle,
    state: tauri::State<'_, Vault>,
) -> Result<Vec<dto::StagedAttachment>, String> {
    use tauri_plugin_dialog::DialogExt;

    let (tx, rx) = std::sync::mpsc::channel();
    app.dialog().file().pick_files(move |paths| {
        let _ = tx.send(paths);
    });

    let picked = rx.recv().map_err(|e| format!("Dateiauswahl fehlgeschlagen: {e}"))?;
    let Some(paths) = picked else { return Ok(Vec::new()) };

    let paths = paths
        .into_iter()
        .map(|p| p.into_path().map_err(|e| format!("Pfad nicht lesbar: {e}")))
        .collect::<Result<Vec<_>, _>>()?;

    let mut vault = lock(&state)?;
    stage_paths(&mut vault, paths)
}

/// Liest Dateien ein und legt sie im Zwischenspeicher ab.
///
/// Gemeinsamer Weg für den Auswahldialog und für Dateien, die aufs Fenster
/// gezogen werden (siehe `lib.rs`). Einen Befehl, der beliebige Pfade aus
/// der Oberfläche annimmt, gibt es bewusst nicht — sonst könnte der Webview
/// jede Datei des Benutzers in die Datenbank und damit zu sich holen. Die
/// Pfade kommen immer vom System: aus dem Dialog oder aus dem Ablegen.
pub fn stage_paths(
    vault: &mut crate::state::VaultState,
    paths: Vec<std::path::PathBuf>,
) -> Result<Vec<dto::StagedAttachment>, String> {
    let mut staged = Vec::new();

    for path in paths {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "Anhang".into());

        let size = std::fs::metadata(&path)
            .map_err(|e| format!("„{name}“ nicht lesbar: {e}"))?
            .len();

        if size > MAX_ATTACHMENT_BYTES {
            return Err(format!(
                "„{name}“ ist {:.1} MB groß. Mehr als 2 MB je Anhang nimmt die Datenbank nicht.",
                size as f64 / (1024.0 * 1024.0)
            ));
        }

        let bytes = std::fs::read(&path).map_err(|e| format!("„{name}“ nicht lesbar: {e}"))?;

        let reference = format!("{STAGED_PREFIX}{}", vault.new_token());
        let mime = mime_from_name(&name);

        vault.staged.insert(
            reference.clone(),
            crate::state::StagedAttachment { name: name.clone(), bytes },
        );

        staged.push(dto::StagedAttachment { name, mime, size, reference });
    }

    Ok(staged)
}

fn mime_from_name(name: &str) -> String {
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default();

    match ext.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "pdf" => "application/pdf",
        "json" => "application/json",
        "txt" | "md" | "csv" => "text/plain",
        _ => "application/octet-stream",
    }
    .to_string()
}

/* =========================================================
   Passwortstärke
   ---------------------------------------------------------
   Wortgleiche Übersetzung von `passwordStrength` aus js/security.js. Die
   Anzeige muss dieselbe bleiben, egal ob Rust oder das Demo-Backend rechnet.

   Wichtig: COMMON ist hier bewusst ein Array und kein HashSet. Die
   Vorlage läuft die Liste in Einfügereihenfolge durch und bricht beim
   ersten Treffer ab — mit einer zufälligen Reihenfolge käme bei
   Passwörtern mit zwei Treffern ein anderer Abzug heraus.
   ========================================================= */

const COMMON: [&str; 22] = [
    "passwort", "password", "passwort1", "123456", "12345678", "123456789", "qwertz",
    "qwerty", "hallo", "admin", "letmein", "welcome", "monkey", "dragon", "iloveyou",
    "sonnenschein", "fussball", "schatz", "ficken", "arschloch", "daniel", "master",
];

const SEQUENCES: [&str; 4] = [
    "abcdefghijklmnopqrstuvwxyz",
    "01234567890",
    "qwertzuiopasdfghjklyxcvbnm",
    "qwertyuiopasdfghjklzxcvbnm",
];

#[tauri::command]
pub fn vault_strength(
    state: tauri::State<'_, Vault>,
    token: String,
) -> Result<dto::Strength, String> {
    Ok(strength(&take(&state, &token)?))
}

fn strength(pw: &str) -> dto::Strength {
    let mut hints: Vec<String> = Vec::new();

    if pw.is_empty() {
        return dto::Strength {
            score: 0,
            entropy: 0,
            label: "leer".into(),
            hints: vec!["Kein Passwort gesetzt.".into()],
        };
    }

    let mut pool = 0u32;
    if pw.chars().any(|c| c.is_ascii_lowercase()) { pool += 26; }
    if pw.chars().any(|c| c.is_ascii_uppercase()) { pool += 26; }
    if pw.chars().any(|c| c.is_ascii_digit()) { pool += 10; }
    if pw.chars().any(|c| !c.is_ascii_alphanumeric()) { pool += 33; }

    let length = pw.chars().count() as f64;
    let mut entropy = length * f64::from(pool.max(1)).log2();

    let lower = pw.to_lowercase();

    if COMMON.contains(&lower.as_str()) {
        entropy -= 40.0;
        hints.push("Steht auf Listen häufiger Passwörter.".into());
    }

    for word in COMMON {
        if word.len() >= 5 && lower.contains(word) {
            // Je mehr des Passworts aus dem bekannten Wort besteht, desto
            // stärker der Abzug.
            let share = word.chars().count() as f64 / length;
            entropy -= 14.0 + (share * 34.0).round();
            hints.push(format!("Enthält das gängige Wort „{word}“."));
            break;
        }
    }

    let mut chars = pw.chars();
    let first = chars.clone().next();
    if first.is_some() && chars.all(|c| Some(c) == first) {
        entropy -= 25.0;
        hints.push("Besteht nur aus einem wiederholten Zeichen.".into());
    }

    if has_run_of(pw, 3) {
        entropy -= 8.0;
        hints.push("Enthält mehrfach wiederholte Zeichen.".into());
    }

    'sequences: for seq in SEQUENCES {
        let letters: Vec<char> = seq.chars().collect();
        for window in letters.windows(4) {
            let part: String = window.iter().collect();
            let backwards: String = window.iter().rev().collect();

            if lower.contains(&part) || lower.contains(&backwards) {
                entropy -= 12.0;
                hints.push("Enthält eine Tastatur- oder Alphabet-Reihenfolge.".into());
                break 'sequences;
            }
        }
    }

    if pw.chars().all(|c| c.is_ascii_digit()) {
        entropy -= 12.0;
        hints.push("Besteht nur aus Ziffern.".into());
    }

    if looks_like_a_year(pw) {
        entropy -= 10.0;
        hints.push("Sieht aus wie eine Jahreszahl.".into());
    }

    if length < 8.0 { hints.push("Kürzer als 8 Zeichen.".into()); }
    if !pw.chars().any(|c| c.is_ascii_uppercase()) { hints.push("Keine Großbuchstaben.".into()); }
    if !pw.chars().any(|c| !c.is_ascii_alphanumeric()) { hints.push("Keine Sonderzeichen.".into()); }

    entropy = entropy.max(0.0);

    let score = match entropy {
        e if e < 28.0 => 0,
        e if e < 40.0 => 1,
        e if e < 60.0 => 2,
        e if e < 80.0 => 3,
        _ => 4,
    };

    const LABELS: [&str; 5] = ["sehr schwach", "schwach", "mittel", "stark", "sehr stark"];

    // Reihenfolge erhalten, Doppelte entfernen — wie `new Set(hints)`.
    let mut unique: Vec<String> = Vec::with_capacity(hints.len());
    for hint in hints {
        if !unique.contains(&hint) {
            unique.push(hint);
        }
    }

    dto::Strength {
        score,
        entropy: entropy.round() as u32,
        label: LABELS[score as usize].into(),
        hints: unique,
    }
}

/// Kommt irgendein Zeichen `count`-mal hintereinander vor?
fn has_run_of(pw: &str, count: usize) -> bool {
    let chars: Vec<char> = pw.chars().collect();
    chars.windows(count).any(|w| w.iter().all(|c| *c == w[0]))
}

fn looks_like_a_year(pw: &str) -> bool {
    pw.len() == 4
        && (pw.starts_with("19") || pw.starts_with("20"))
        && pw.chars().all(|c| c.is_ascii_digit())
}
