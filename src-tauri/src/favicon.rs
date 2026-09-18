//! Website-Icons: einmal holen, dann in der Datenbank.
//!
//! Früher lud die Oberfläche jedes Icon bei jeder Anzeige neu von der Seite
//! selbst. Das scheitert bei allem, was nur in einem bestimmten Netz
//! erreichbar ist — der NAS daheim, das Firmen-Wiki —, und jede Anzeige
//! verriet der Seite die eigene Adresse.
//!
//! Jetzt landet das Icon als **Custom Icon** im Eintrag, genau wie bei
//! KeePassXC („Favicon herunterladen"). Damit liegt es verschlüsselt in der
//! Datei statt als Liste der eigenen Dienste im Klartext auf der Platte, und
//! wer die Datei auf mehreren Geräten nutzt, hat es überall.
//!
//! # Wann geholt wird
//!
//! Möglichst dann, wenn die Seite sicher erreichbar ist: beim Anmelden über
//! Browser-Erweiterung oder Autofill, beim Benutzen eines Eintrags — und
//! nach dem Entsperren für alle, denen noch eines fehlt. Was nicht klappt,
//! wird eine Viertelstunde lang nicht erneut versucht; im nächsten Netz
//! kann es dann gehen.

use std::collections::{HashMap, HashSet};
use std::io::Cursor;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use keepass::db::{CustomIconId, EntryId, Icon};
use tauri::{Emitter, Manager};

use crate::web;
use crate::Vault;

/// Kantenlänge, auf die verkleinert wird — scharf genug für jede Liste,
/// klein genug, dass hundert Icons die Datei kaum wachsen lassen.
const KANTE: u32 = 64;

/// So lange wird eine Seite nach einem Fehlschlag in Ruhe gelassen.
const ERNEUT_NACH: Duration = Duration::from_secs(15 * 60);

fn fehlschlaege() -> &'static Mutex<HashMap<String, Instant>> {
    static F: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    F.get_or_init(Default::default)
}

/// Seiten, die gerade geholt werden — damit zwei Anlässe nicht doppelt laden.
fn laufend() -> &'static Mutex<HashSet<String>> {
    static L: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    L.get_or_init(Default::default)
}

/// Von wo aus gesucht wird: Schema, Rechner und Port der Adresse.
///
/// Ohne Schema erst `https`, dann `http`. Adressen anderer Art
/// (`androidapp://…`, `ssh://…`) haben kein Icon im Netz.
fn basis(url: &str) -> Vec<String> {
    let url = url.trim();
    let (schema, rest) = match url.split_once("://") {
        Some((s, r)) => (Some(s.to_ascii_lowercase()), r),
        None => (None, url),
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let authority = authority.rsplit_once('@').map_or(authority, |(_, r)| r);
    if authority.is_empty() || authority.contains(char::is_whitespace) {
        return Vec::new();
    }

    match schema.as_deref() {
        Some(s @ ("http" | "https")) => vec![format!("{s}://{authority}")],
        Some(_) => Vec::new(),
        // Ein bloßes Wort ist kein Rechnername, den man ansprechen sollte.
        None if !authority.contains(['.', ':']) => Vec::new(),
        None => vec![format!("https://{authority}"), format!("http://{authority}")],
    }
}

/// Schlüssel für Fehlschläge und laufende Abrufe.
fn schluessel(url: &str) -> Option<String> {
    basis(url).into_iter().next()
}

/// Holt das Icon einer Seite, als PNG mit höchstens 64 × 64 Pixeln.
pub fn holen(url: &str) -> Option<Vec<u8>> {
    for base in basis(url) {
        let mut kandidaten = Vec::new();

        match web::get(&format!("{base}/"), 512 * 1024) {
            Ok(seite) => {
                if seite.typ.is_empty() || seite.typ.contains("html") {
                    kandidaten.extend(web::icon_links(&String::from_utf8_lossy(&seite.body), &seite.url));
                }
            }
            // Gar nicht erreichbar: Die festen Pfade dort lohnen nicht.
            Err(web::Fehler::Netz(_)) => continue,
            Err(web::Fehler::Antwort(_)) => {}
        }

        kandidaten.push(format!("{base}/favicon.ico"));
        kandidaten.push(format!("{base}/apple-touch-icon.png"));

        let mut gesehen = HashSet::new();
        for k in kandidaten.into_iter().filter(|k| gesehen.insert(k.clone())) {
            if let Some(png) = web::get(&k, 1024 * 1024).ok().and_then(|a| als_png(&a.body)) {
                return Some(png);
            }
        }
    }
    None
}

/// Bringt ein Bild beliebigen Formats in ein kleines PNG.
fn als_png(bytes: &[u8]) -> Option<Vec<u8>> {
    let bild = image::load_from_memory(bytes).ok()?;
    if bild.width() < 8 || bild.height() < 8 {
        return None;
    }
    let bild = if bild.width().max(bild.height()) > KANTE {
        bild.resize(KANTE, KANTE, image::imageops::FilterType::Lanczos3)
    } else {
        bild
    };
    let mut out = Vec::new();
    bild.write_to(&mut Cursor::new(&mut out), image::ImageFormat::Png).ok()?;
    Some(out)
}

/// Das Icon eines Eintrags als `data:`-Adresse für die Oberfläche.
pub fn data_url(entry: &keepass::db::EntryRef<'_>) -> Option<String> {
    use base64::Engine;

    let icon = entry.custom_icon()?;
    let mime = match icon.data.as_slice() {
        [0x89, b'P', b'N', b'G', ..] => "image/png",
        [0xFF, 0xD8, ..] => "image/jpeg",
        [0, 0, 1, 0, ..] => "image/x-icon",
        [b'G', b'I', b'F', ..] => "image/gif",
        [b'R', b'I', b'F', b'F', ..] => "image/webp",
        d if d.starts_with(b"<svg") || d.starts_with(b"<?xml") => "image/svg+xml",
        _ => "image/png",
    };
    Some(format!("data:{mime};base64,{}", base64::engine::general_purpose::STANDARD.encode(&icon.data)))
}

/// Hängt ein Icon an einen Eintrag. Dasselbe Bild wird nur einmal
/// gespeichert, auch wenn es mehrere Einträge nutzen.
///
/// Liefert das Icon, das der Eintrag vorher hatte — das ist womöglich jetzt
/// verwaist (siehe `aufraeumen`).
fn anhaengen(db: &mut keepass::Database, id: EntryId, png: Vec<u8>) -> Option<CustomIconId> {
    let vorhanden = db.iter_all_custom_icons().find(|i| i.data == png).map(|i| i.id());
    let mut entry = db.entry_mut(id)?;
    let vorher = match entry.icon() {
        Some(Icon::Custom(alt)) => Some(*alt),
        _ => None,
    };
    match vorhanden {
        Some(icon) => {
            let _ = entry.set_icon_custom(icon);
        }
        None => {
            entry.set_icon_custom_new(png);
        }
    }
    vorher
}

/// Entfernt die ersetzten Icons, wenn sie nun niemand mehr nutzt — sonst
/// sammelten sich beim Neuladen alte Fassungen in der Datei. Nur diese: Was
/// jemand anderes in der Datei abgelegt hat, bleibt, auch wenn es unbenutzt ist.
fn aufraeumen(db: &mut keepass::Database, ersetzt: impl IntoIterator<Item = CustomIconId>) {
    for id in ersetzt {
        let verwaist = db
            .custom_icon(id)
            .is_some_and(|i| i.entries(true).next().is_none() && i.groups().next().is_none());
        if verwaist {
            if let Some(icon) = db.custom_icon_mut(id) {
                icon.remove();
            }
        }
    }
}

/// Dürfen Icons geladen werden? Die Einstellung „Website-Icons".
fn erlaubt(app: &tauri::AppHandle) -> bool {
    crate::settings::value(app, "icons.download").and_then(|v| v.as_bool()).unwrap_or(true)
}

/// Holt im Hintergrund die Icons für `ids` — oder für alle Einträge, denen
/// eines fehlt, wenn `ids` leer ist. Mit `neu` auch für die, die schon eines
/// haben.
///
/// Kehrt sofort zurück — alles Weitere, auch das Sperren der Datenbank,
/// passiert in einem eigenen Faden. Aufrufer dürfen die Sperre also gerade
/// selbst halten. Ist etwas dazugekommen, wird gespeichert und die
/// Oberfläche bekommt `vault-changed`.
pub fn im_hintergrund(app: &tauri::AppHandle, ids: Vec<String>, neu: bool) {
    if !erlaubt(app) {
        return;
    }
    let app = app.clone();
    std::thread::spawn(move || abrufen(&app, &ids, neu));
}

fn abrufen(app: &tauri::AppHandle, ids: &[String], neu: bool) {
    // Was zu holen ist, unter der Sperre einsammeln — geladen wird ohne.
    let auftraege: Vec<(EntryId, String)> = {
        let state = app.state::<Vault>();
        let Ok(vault) = state.lock() else { return };
        let Ok(db) = vault.database() else { return };
        let jetzt = Instant::now();
        let fehl = fehlschlaege().lock().map(|f| f.clone()).unwrap_or_default();

        db.iter_all_entries()
            .filter(|e| ids.is_empty() || ids.iter().any(|id| *id == e.id().uuid().to_string()))
            .filter(|e| neu || !matches!(e.icon(), Some(Icon::Custom(_))))
            .filter_map(|e| {
                let url = e.get_url().unwrap_or_default().to_string();
                let k = schluessel(&url)?;
                let gesperrt = !neu && fehl.get(&k).is_some_and(|t| jetzt.duration_since(*t) < ERNEUT_NACH);
                (!gesperrt).then_some((e.id(), url))
            })
            .collect()
    };
    if auftraege.is_empty() {
        return;
    }

    {
        // Je Seite nur einmal laden, auch wenn mehrere Einträge darauf zeigen.
        let mut je_seite: HashMap<String, Vec<(EntryId, String)>> = HashMap::new();
        for (id, url) in auftraege {
            if let Some(k) = schluessel(&url) {
                je_seite.entry(k).or_default().push((id, url));
            }
        }

        let mut ergebnisse: Vec<(EntryId, Vec<u8>)> = Vec::new();
        for (k, eintraege) in je_seite {
            if !laufend().lock().is_ok_and(|mut l| l.insert(k.clone())) {
                continue;
            }
            let png = holen(&eintraege[0].1);
            if let Ok(mut l) = laufend().lock() {
                l.remove(&k);
            }
            match png {
                Some(png) => ergebnisse.extend(eintraege.into_iter().map(|(id, _)| (id, png.clone()))),
                None => {
                    if let Ok(mut f) = fehlschlaege().lock() {
                        f.insert(k, Instant::now());
                    }
                }
            }
        }
        if ergebnisse.is_empty() {
            return;
        }

        {
            let state = app.state::<Vault>();
            let Ok(mut vault) = state.lock() else { return };
            let Ok(db) = vault.database_mut() else { return };
            let ersetzt: Vec<_> = ergebnisse.into_iter().filter_map(|(id, png)| anhaengen(db, id, png)).collect();
            aufraeumen(db, ersetzt);
        }

        // Scheitert das Speichern (nur lesbar, gerade offline), stehen die
        // Icons trotzdem im Speicher und gehen beim nächsten Speichern mit.
        let _ = crate::database::commit(app, &app.state::<Vault>());
        let _ = app.emit("vault-changed", ());
    }
}

/// Die Oberfläche fordert Icons an: nach dem Entsperren für alle, denen eines
/// fehlt, beim Benutzen für einzelne, auf Knopfdruck neu.
#[tauri::command]
pub fn vault_fetch_icons(app: tauri::AppHandle, ids: Option<Vec<String>>, force: Option<bool>) {
    im_hintergrund(&app, ids.unwrap_or_default(), force.unwrap_or(false));
}

/// Entfernt das Icon eines Eintrags.
#[tauri::command]
pub fn vault_clear_icon(state: tauri::State<'_, Vault>, id: String) -> Result<bool, String> {
    let mut vault = state.lock().map_err(|_| "Kern blockiert.".to_string())?;
    let db = vault.database_mut()?;
    let Some(eid) = db.iter_all_entries().find(|e| e.id().uuid().to_string() == id).map(|e| e.id()) else {
        return Ok(false);
    };
    let mut ersetzt = None;
    if let Some(mut e) = db.entry_mut(eid) {
        if let Some(Icon::Custom(alt)) = e.icon() {
            ersetzt = Some(*alt);
        }
        e.set_icon_none();
    }
    aufraeumen(db, ersetzt);
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basis_nimmt_schema_und_port() {
        assert_eq!(basis("http://nas.fritz.box:5000/login"), vec!["http://nas.fritz.box:5000"]);
        assert_eq!(basis("github.com/login"), vec!["https://github.com", "http://github.com"]);
        assert_eq!(basis("https://user:pw@example.org"), vec!["https://example.org"]);
        assert!(basis("androidapp://com.example").is_empty());
        assert!(basis("Notiz").is_empty());
    }

    /// Geht ins Netz — nur von Hand: `cargo test -- --ignored favicon`.
    #[test]
    #[ignore]
    fn holt_ein_echtes_icon() {
        let png = holen("github.com").expect("kein Icon");
        assert!(png.starts_with(&[0x89, b'P', b'N', b'G']));
        let bild = image::load_from_memory(&png).unwrap();
        assert!(bild.width() <= KANTE && bild.height() <= KANTE);
    }
}
