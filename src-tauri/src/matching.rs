//! Welcher Eintrag passt zu welcher Adresse?
//!
//! Gemeinsam für die Browser-Anbindung auf dem Desktop und das Autofill auf
//! Android: Beide stellen dieselbe Frage, nur kommt die Adresse einmal von
//! der Erweiterung und einmal von Android selbst.
//!
//! Auf Android ist es oft gar keine Webadresse, sondern ein Paketname. Den
//! schreiben wir wie KeePassDX und Keepass2Android als
//! `androidapp://com.beispiel.app` an den Eintrag — dann greift hier
//! dieselbe Rechnung, der Paketname ist der „Rechner".

use keepass::db::EntryRef;

/// Alle Adressen eines Eintrags: das Adressfeld und `KP_ADDITIONAL_URL*`.
pub fn entry_urls(entry: &EntryRef<'_>) -> Vec<String> {
    std::iter::once(entry.get_url().unwrap_or_default().to_string())
        .chain(
            entry
                .fields
                .iter()
                .filter(|(name, _)| name.starts_with("KP_ADDITIONAL_URL"))
                .map(|(_, value)| value.to_string()),
        )
        .filter(|u| !u.trim().is_empty())
        .collect()
}

/// Der Rechnername einer Adresse, ohne Anmeldedaten, Port und Pfad.
pub fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let rest = rest.split(['/', '?', '#']).next()?;
    let rest = rest.rsplit_once('@').map(|(_, r)| r).unwrap_or(rest);
    let host = rest.split(':').next()?.trim().to_ascii_lowercase();

    (!host.is_empty()).then_some(host)
}

/// Rechnername und Pfad einer Adresse, ohne Anmeldedaten, Port und Anhängsel.
pub fn split_url(url: &str) -> Option<(String, Vec<String>)> {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let rest = rest.split(['?', '#']).next()?;

    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, p),
        None => (rest, ""),
    };

    let authority = authority.rsplit_once('@').map(|(_, r)| r).unwrap_or(authority);
    let host = authority.split(':').next()?.trim().to_ascii_lowercase();

    if host.is_empty() {
        return None;
    }

    let segments = path.split('/').filter(|s| !s.is_empty()).map(str::to_string).collect();
    Ok::<_, ()>((host, segments)).ok()
}

/// Wie gut passt der Eintrag zur angefragten Adresse?
///
/// `None` heißt: gar nicht. Sonst gilt: je größer, desto genauer.
///
/// # Die Reihenfolge, in der gesucht wird
///
/// Zuerst die genaue Adresse, dann Stück für Stück gröber:
///
/// ```text
/// https://shop.example.com/kunden/login     angefragt
///
///   shop.example.com/kunden/login    genau              120
///   shop.example.com/kunden          Pfad ein Stück ab  110
///   shop.example.com                 nur der Rechner    100
///   example.com                      eine Ebene höher    90
/// ```
///
/// Ein Eintrag mit abweichendem Pfad — etwa `/impressum` — fällt nicht
/// heraus, sondern nur ans Ende. Sonst käme man an einen Eintrag, den man
/// für die Domain angelegt hat, auf einer Unterseite nicht mehr heran.
///
/// Zurückgegeben wird alles Passende, nach Genauigkeit sortiert. Die
/// Auswahl trifft der Nutzer danach in der Liste, die die Erweiterung
/// selbst in die Seite zeichnet.
pub fn match_score(entry_url: &str, wanted_host: &str, wanted_path: &[String]) -> Option<u32> {
    let (host, path) = split_url(entry_url)?;

    // Der Rechner entscheidet, ob es überhaupt passt.
    let host_score = if host == wanted_host {
        100
    } else if let Some(rest) = wanted_host.strip_suffix(&format!(".{host}")) {
        // Je mehr Unterebenen dazwischen liegen, desto entfernter.
        let ebenen = rest.matches('.').count() as u32 + 1;
        90u32.saturating_sub((ebenen - 1) * 10)
    } else {
        return None;
    };

    // Der Pfad verfeinert nur noch.
    let gemeinsam = entry_path_prefix(&path, wanted_path);

    Some(match gemeinsam {
        // Kein Pfad am Eintrag: gilt für die ganze Seite, ohne Abzug.
        Some(0) => host_score,
        Some(n) => host_score + 10 + n.min(2) as u32 * 5,
        // Pfad passt nicht — trotzdem behalten, aber ganz hinten.
        None => host_score.saturating_sub(50),
    })
}

/// Wie viele Pfadstücke des Eintrags am Anfang der Anfrage stehen.
///
/// `None`, wenn der Eintrag einen Pfad hat, der nicht dazu passt.
fn entry_path_prefix(entry: &[String], wanted: &[String]) -> Option<usize> {
    if entry.is_empty() {
        return Some(0);
    }
    if entry.len() > wanted.len() {
        return None;
    }
    entry
        .iter()
        .zip(wanted)
        .all(|(a, b)| a == b)
        .then_some(entry.len())
}

