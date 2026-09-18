//! Abrufe aus dem Netz: Website-Icons und -Titel.
//!
//! Aus dem Webview geht das nicht — fremde Seiten sperren das Auslesen
//! ihrer Antworten per CORS. Hier im Kern gibt es diese Grenze nicht.
//!
//! Was dabei **nicht** mitgeht: Cookies, Anmeldedaten, irgendetwas aus der
//! Datenbank. Nur eine nackte GET-Anfrage an die Adresse des Eintrags, wie
//! sie jeder Besucher der Seite stellt.
//!
//! # Zertifikate
//!
//! Geprüft wird nicht. Viele der Dienste, um die es hier geht, stehen im
//! Heimnetz — Router, NAS, Drucker — und haben ein selbst ausgestelltes
//! Zertifikat. Mit Prüfung gäbe es genau dort nie ein Icon. Das ist
//! vertretbar, weil nichts gesendet wird: Wer die Verbindung fälscht,
//! könnte höchstens ein falsches Bildchen unterschieben.

use std::time::Duration;

use ureq::tls::TlsConfig;
use ureq::ResponseExt;

/// Eine geladene Antwort.
pub struct Antwort {
    /// Die Adresse nach allen Weiterleitungen — Grundlage für relative Links.
    pub url: String,
    /// `content-type`, klein geschrieben, ohne Parameter.
    pub typ: String,
    pub body: Vec<u8>,
}

/// Warum ein Abruf scheiterte.
#[derive(Debug)]
pub enum Fehler {
    /// Die Gegenstelle ist nicht erreichbar — weitere Pfade dort lohnen nicht.
    Netz(String),
    /// Erreichbar, aber nicht das Gewünschte (404, zu groß, …).
    Antwort(String),
}

impl std::fmt::Display for Fehler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Fehler::Netz(e) | Fehler::Antwort(e) => f.write_str(e),
        }
    }
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(8)))
        .max_redirects(5)
        .http_status_as_error(false)
        // Ein gewöhnlicher Browser — manche Seiten liefern einem
        // unbekannten Abrufer sonst eine Fehlerseite statt ihres Icons.
        .user_agent("Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0")
        .tls_config(TlsConfig::builder().disable_verification(true).build())
        .build()
        .into()
}

/// Lädt `url`, höchstens `limit` Bytes.
pub fn get(url: &str, limit: u64) -> Result<Antwort, Fehler> {
    let mut res = agent().get(url).call().map_err(|e| Fehler::Netz(e.to_string()))?;

    if !res.status().is_success() {
        return Err(Fehler::Antwort(format!("HTTP {}", res.status())));
    }

    let typ = res
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let url = res.get_uri().to_string();
    let body = res
        .body_mut()
        .with_config()
        .limit(limit)
        .read_to_vec()
        .map_err(|e| Fehler::Antwort(e.to_string()))?;

    Ok(Antwort { url, typ, body })
}

/* =========================================================
   Ein wenig HTML
   ---------------------------------------------------------
   Kein Parser — gesucht werden nur `<link …>` und `<title>`, und die sind
   so einfach gebaut, dass ein Durchlauf über den Text genügt.
   ========================================================= */

/// Die Attribute eines Tags: `<link rel="icon" href=/a.png>` → rel, href.
fn attribute(tag: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rest = tag;

    while let Some(start) = rest.find(|c: char| c.is_ascii_alphabetic()) {
        rest = &rest[start..];
        let ende = rest.find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_')).unwrap_or(rest.len());
        let name = rest[..ende].to_ascii_lowercase();
        rest = rest[ende..].trim_start();

        if let Some(nach) = rest.strip_prefix('=') {
            let nach = nach.trim_start();
            let (wert, weiter) = match nach.chars().next() {
                Some(q @ ('"' | '\'')) => {
                    let inhalt = &nach[1..];
                    let e = inhalt.find(q).unwrap_or(inhalt.len());
                    (&inhalt[..e], &inhalt[(e + 1).min(inhalt.len())..])
                }
                _ => {
                    let e = nach.find(|c: char| c.is_whitespace() || c == '>').unwrap_or(nach.len());
                    (&nach[..e], &nach[e..])
                }
            };
            out.push((name, entities(wert)));
            rest = weiter;
        } else {
            out.push((name, String::new()));
        }
    }
    out
}

/// Alle `<name …>`-Tags eines Dokuments, ohne die spitzen Klammern.
fn tags<'a>(html: &'a str, name: &str) -> Vec<&'a str> {
    let klein = html.to_ascii_lowercase();
    let muster = format!("<{name}");
    let mut out = Vec::new();
    let mut pos = 0;

    while let Some(i) = klein[pos..].find(&muster) {
        let start = pos + i + muster.len();
        // `<linkfoo` ist kein `<link`.
        if !klein[start..].starts_with(|c: char| c.is_whitespace() || c == '/' || c == '>') {
            pos = start;
            continue;
        }
        let ende = klein[start..].find('>').map_or(klein.len(), |e| start + e);
        out.push(&html[start..ende]);
        pos = ende;
    }
    out
}

/// Die Icon-Verweise einer Seite, das beste zuerst.
///
/// Bevorzugt das Symbol für den Startbildschirm (`apple-touch-icon`): meist
/// 180 Pixel und damit scharf. Danach `icon` mit der größten Angabe unter
/// `sizes`. SVG fällt weg — das kann `image` nicht zeichnen.
pub fn icon_links(html: &str, seite: &str) -> Vec<String> {
    let Ok(basis) = url::Url::parse(seite) else { return Vec::new() };
    let mut treffer: Vec<(u32, String)> = Vec::new();

    for tag in tags(html, "link") {
        let attr = attribute(tag);
        let get = |n: &str| attr.iter().find(|(k, _)| k == n).map(|(_, v)| v.as_str());

        let rel = get("rel").unwrap_or_default().to_ascii_lowercase();
        let Some(href) = get("href").filter(|h| !h.is_empty()) else { continue };
        if !rel.split_whitespace().any(|r| r == "icon" || r.starts_with("apple-touch-icon")) {
            continue;
        }
        if get("type").is_some_and(|t| t.contains("svg")) || href.to_ascii_lowercase().split('?').next().is_some_and(|p| p.ends_with(".svg")) {
            continue;
        }

        let groesse = get("sizes")
            .and_then(|s| s.split_whitespace().filter_map(|g| g.split(['x', 'X']).next()?.parse::<u32>().ok()).max())
            .unwrap_or(if rel.contains("apple-touch-icon") { 180 } else { 16 });

        if let Ok(ziel) = basis.join(href) {
            if matches!(ziel.scheme(), "http" | "https") {
                treffer.push((groesse, ziel.to_string()));
            }
        }
    }

    treffer.sort_by(|a, b| b.0.cmp(&a.0));
    treffer.into_iter().map(|(_, u)| u).collect()
}

/// Der Inhalt von `<title>`, ohne überflüssigen Leerraum.
pub fn title(html: &str) -> Option<String> {
    let klein = html.to_ascii_lowercase();
    let start = klein.find("<title")?;
    let start = start + klein[start..].find('>')? + 1;
    let ende = start + klein[start..].find("</title")?;
    let text = entities(&html[start..ende]).split_whitespace().collect::<Vec<_>>().join(" ");
    (!text.is_empty()).then_some(text)
}

/// Der Name des Dienstes — für den Namen eines Eintrags.
///
/// Der Seitentitel allein taugt selten: „Anmelden – Amazon.de“ oder
/// „GitHub · Build and ship software on a single, collaborative platform“.
/// Deshalb der Reihe nach:
///
/// 1. was die Seite selbst als ihren Namen angibt (`og:site_name`,
///    `application-name`, `apple-mobile-web-app-title`),
/// 2. aus dem Titel das Stück, in dem die Domain steckt,
/// 3. ein kurzer Titel ohne Trenner,
/// 4. die Domain selbst: `github.com` → „Github“.
pub fn dienstname(html: &str, seite: &str) -> Option<String> {
    let basis = domain_basis(seite);

    for tag in tags(html, "meta") {
        let attr = attribute(tag);
        let get = |n: &str| attr.iter().find(|(k, _)| k == n).map(|(_, v)| v.trim().to_string());
        let art = get("property").or_else(|| get("name")).unwrap_or_default().to_ascii_lowercase();
        if matches!(art.as_str(), "og:site_name" | "application-name" | "apple-mobile-web-app-title") {
            if let Some(name) = get("content").filter(|c| !c.is_empty() && c.chars().count() <= 40) {
                return Some(name);
            }
        }
    }

    if let Some(titel) = title(html) {
        const TRENNER: [&str; 8] = [" | ", " – ", " — ", " - ", " · ", " • ", " :: ", " » "];
        let mut teile = vec![titel.clone()];
        for t in TRENNER {
            teile = teile.iter().flat_map(|x| x.split(t).map(str::trim).map(String::from).collect::<Vec<_>>()).collect();
        }
        teile.retain(|t| !t.is_empty());

        if let Some(b) = basis.as_deref() {
            let passt = |t: &str| {
                let klein: String = t.to_lowercase().chars().filter(|c| c.is_alphanumeric()).collect();
                klein.contains(b) || (klein.len() >= 3 && b.contains(&klein))
            };
            if let Some(t) = teile.iter().filter(|t| passt(t)).min_by_key(|t| t.chars().count()) {
                if t.chars().count() <= 40 {
                    return Some(t.clone());
                }
            }
        }
        if teile.len() == 1 && titel.chars().count() <= 30 {
            return Some(titel);
        }
    }

    basis.map(|b| {
        let mut c = b.chars();
        c.next().map(|f| f.to_uppercase().chain(c).collect()).unwrap_or_default()
    })
}

/// `https://login.example.co.uk/x` → `example`: der Teil vor der Endung.
fn domain_basis(seite: &str) -> Option<String> {
    let host = url::Url::parse(seite).ok()?.host_str()?.to_ascii_lowercase();
    let teile: Vec<&str> = host.split('.').filter(|t| !t.is_empty()).collect();
    if teile.len() < 2 {
        return teile.first().map(|t| t.to_string());
    }
    // Zweistufige Endungen (co.uk, com.au …): dann eins weiter vorn
    let zweistufig = teile.len() >= 3 && teile[teile.len() - 2].len() <= 3 && teile[teile.len() - 1].len() == 2;
    let i = if zweistufig { teile.len() - 3 } else { teile.len() - 2 };
    Some(teile[i].to_string())
}

/// Die gängigen HTML-Entitäten zurück in Zeichen.
fn entities(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;

    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let Some(ende) = rest[..rest.len().min(12)].find(';') else {
            out.push('&');
            rest = &rest[1..];
            continue;
        };
        let name = &rest[1..ende];
        let zeichen = match name {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" | "#39" => Some('\''),
            "nbsp" => Some(' '),
            n if n.starts_with("#x") || n.starts_with("#X") => u32::from_str_radix(&n[2..], 16).ok().and_then(char::from_u32),
            n if n.starts_with('#') => n[1..].parse().ok().and_then(char::from_u32),
            _ => None,
        };
        match zeichen {
            Some(c) => {
                out.push(c);
                rest = &rest[ende + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn findet_icons_und_bevorzugt_grosse() {
        let html = r#"<head><LINK rel="shortcut icon" href="/favicon.ico">
            <link rel=apple-touch-icon href="touch.png">
            <link rel="icon" type="image/svg+xml" href="/a.svg">
            <link rel="icon" sizes="32x32" href='//cdn.example.org/32.png'></head>"#;
        let links = icon_links(html, "https://example.org/start/");
        assert_eq!(links, vec![
            "https://example.org/start/touch.png",
            "https://cdn.example.org/32.png",
            "https://example.org/favicon.ico",
        ]);
    }

    #[test]
    fn dienstname_statt_seitentitel() {
        let og = r#"<meta property="og:site_name" content="GitHub"><title>GitHub · Build and ship software</title>"#;
        assert_eq!(dienstname(og, "https://github.com/login").as_deref(), Some("GitHub"));
        let lang = "<title>Anmelden – Amazon.de</title>";
        assert_eq!(dienstname(lang, "https://www.amazon.de/ap/signin").as_deref(), Some("Amazon.de"));
        let kurz = "<title>Nextcloud</title>";
        assert_eq!(dienstname(kurz, "https://cloud.example.org").as_deref(), Some("Nextcloud"));
        let nichts = "<title>Willkommen auf unserer Seite, schön dass Sie da sind</title>";
        assert_eq!(dienstname(nichts, "https://shop.example.co.uk/").as_deref(), Some("Example"));
    }

    #[test]
    fn titel_mit_entitaeten() {
        assert_eq!(title("<html><TITLE>\n  Ben &amp; Jerry&#39;s  </title>").as_deref(), Some("Ben & Jerry's"));
        assert_eq!(title("<title></title>"), None);
    }
}
