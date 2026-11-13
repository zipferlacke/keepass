//! Die Gegenstelle der Browser-Erweiterung: beantwortet die Nachrichten, die
//! sonst KeePassXC beantwortet. Manifest, Kanalpfad und Vermittlungsprozess
//! stehen in `route`.
//!
//! # Ablauf einer Sitzung
//!
//! ```text
//! Erweiterung                          Kern
//!     │  change-public-keys  (unverschlüsselt)
//!     │ ─────────────────────────────────▶
//!     │ ◀─────────────────────────────────  öffentlicher Schlüssel des Kerns
//!     │
//!     │  ab jetzt ist alles verschlüsselt
//!     │
//!     │  associate / test-associate       Wiedererkennung
//!     │  get-databasehash                 welche Datenbank ist offen?
//!     │  get-logins                       Zugangsdaten, mit Rückfrage
//! ```
//!
//! # Schlüsselpaare
//!
//! **Sitzungsschlüssel** entstehen bei jeder Verbindung neu und
//! verschlüsseln den Verkehr. Sie sind nach dem Schließen wertlos.
//!
//! **Verknüpfungsschlüssel** entstehen einmal beim erstmaligen Verbinden und
//! werden dauerhaft in der Datenbank gespeichert. Sie verschlüsseln nichts,
//! sondern belegen, dass dieser Browser bereits zugelassen wurde.
//!
//! # Entsperren
//!
//! Über diesen Kanal wird nicht entsperrt; das Master-Passwort durchläuft
//! keinen Code, den eine Website beeinflussen kann. Ist die Datenbank
//! gesperrt, wartet die Anfrage, und das eigene Fenster fragt.

use crate::secrets::current_totp;
use crate::matching::{entry_urls, host_of, match_score, split_url};
#[cfg(not(windows))]
use std::io::{Read, Write};
use std::sync::Mutex;

use serde_json::{json, Value};
use tauri::{Emitter, Manager};

use super::protocol::{self, KeyPair, Nonce, Session};
use super::route;
use crate::Vault;

/// Der Schlüssel, unter dem eine Verknüpfung in der Datenbank steht.
///
/// Dieselbe Form wie bei KeePassXC, damit beide Programme dieselben Browser
/// wiedererkennen.
const ASSOCIATION_PREFIX: &str = "KPXC_BROWSER_";

/// Der gemeldete KeePassXC-Protokollstand (nicht die eigene Programmversion).
///
/// Die Erweiterung wertet das Feld an zwei Stellen aus:
///
///   * `keepass.requiredKeePassXC = '2.6.0'`: niedrigere Versionen werden
///     abgewiesen.
///   * `keePassXCUpdateAvailable()` vergleicht mit der neuesten
///     KeePassXC-Ausgabe von GitHub und zeigt bei einer niedrigeren Zahl
///     einen Update-Hinweis.
///
/// Der Wert entspricht daher einer aktuellen KeePassXC-Ausgabe. Der Hinweis
/// lässt sich in der Erweiterung unter „Nach Updates suchen" abschalten.
const PROTOCOL_VERSION: &str = "2.8.0";

/// Die Fehlercodes der Erweiterung.
///
/// `handleResponse` verzweigt nach dem Code, `kpErrors.getError(code)`
/// liefert daraus den angezeigten Text; Codes außerhalb der Tabelle sind
/// nicht zulässig. Übernommen aus `background/client.js` der Erweiterung.
mod code {
    pub const DATABASE_NOT_OPENED: u16 = 1;
    pub const CANNOT_DECRYPT_MESSAGE: u16 = 4;
    pub const ACTION_CANCELLED_OR_DENIED: u16 = 6;
    pub const ASSOCIATION_FAILED: u16 = 8;
    pub const INCORRECT_ACTION: u16 = 12;
    pub const EMPTY_MESSAGE_RECEIVED: u16 = 13;
    pub const NO_URL_PROVIDED: u16 = 14;
    pub const NO_GROUPS_FOUND: u16 = 16;
    pub const CANNOT_CREATE_NEW_GROUP: u16 = 17;
    pub const NO_VALID_UUID_PROVIDED: u16 = 18;
    pub const PASSKEYS_EMPTY_PUBLIC_KEY: u16 = 24;
    pub const PASSKEYS_REQUEST_CANCELED: u16 = 22;
    pub const PASSKEYS_UNKNOWN_ERROR: u16 = 31;
}

/* =========================================================
   Der lauschende Teil
   ========================================================= */

/// Hängt den Kanal ein und nimmt Verbindungen an.
///
/// Läuft in einem eigenen Thread; jede Verbindung bekommt einen weiteren.
/// Das genügt für eine Handvoll Browser und für Anfragen, die lange auf die
/// Rückfrage beim Nutzer warten.
pub fn start(app: tauri::AppHandle) {
    #[cfg(not(windows))]
    std::thread::spawn(move || {
        if let Err(err) = listen(app) {
            eprintln!("Browser-Anbindung nicht gestartet: {err}");
        }
    });

    #[cfg(windows)]
    tauri::async_runtime::spawn(async move {
        if let Err(err) = pipe::listen(app).await {
            eprintln!("Browser-Anbindung nicht gestartet: {err}");
        }
    });
}

/* ---------------------------------------------------------
   Meldungen an alle verbundenen Browser
   ---------------------------------------------------------
   KeePassXC sagt der Erweiterung von sich aus Bescheid, wenn die
   Datenbank gesperrt oder entsperrt wird (`database-locked` /
   `database-unlocked`, unverschlüsselt). Ohne das hält die Erweiterung
   eine eben gesperrte Datenbank noch für offen und merkt es erst beim
   nächsten Nachfragen — der erste Versuch danach ging ins Leere. Und nach
   dem Entsperren füllt sie erst aus, wenn man die Seite neu lädt.
   --------------------------------------------------------- */

type Notify = Box<dyn Fn(&Value) + Send>;

fn listeners() -> &'static Mutex<std::collections::HashMap<u64, Notify>> {
    static LISTENERS: std::sync::OnceLock<Mutex<std::collections::HashMap<u64, Notify>>> =
        std::sync::OnceLock::new();
    LISTENERS.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

/// Meldet eine Verbindung an; die Nummer braucht es zum Abmelden.
fn register(notify: Notify) -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if let Ok(mut map) = listeners().lock() {
        map.insert(id, notify);
    }
    protokolliere(&format!("Browser {id} verbunden"));
    id
}

fn unregister(id: u64) {
    protokolliere(&format!("Browser {id} getrennt"));
    let leer = match listeners().lock() {
        Ok(mut map) => {
            map.remove(&id);
            map.is_empty()
        }
        Err(_) => false,
    };
    #[cfg(desktop)]
    if leer {
        ohne_browser_beenden(NACHLAUF);
    }
    #[cfg(not(desktop))]
    let _ = leer;
}

/// Ob gerade ein Browser verbunden ist.
#[cfg(desktop)]
fn browser_verbunden() -> bool {
    listeners().lock().map(|map| !map.is_empty()).unwrap_or(true)
}

/* ---------------------------------------------------------
   Im Hintergrund
   ---------------------------------------------------------
   Startet der Browser WKeePass (`route::HINTERGRUND`), bleibt das
   Hauptfenster zu — Rückfragen und Entsperren laufen über das kleine
   Fenster. Die Anwendung lebt dann so lange wie der Browser.

   Dieselbe Regel gilt, wenn man das Hauptfenster schließt, während ein
   Browser verbunden ist: Es verschwindet nur, die Anbindung bleibt. Erst
   wenn der letzte Browser geht und kein Hauptfenster offen ist, endet die
   Anwendung. Öffnet man WKeePass in der Zeit selbst, kommt das Fenster
   nach vorn (Single-Instance in `lib.rs`), und es gilt wieder: Die
   Anwendung lebt, bis man es schließt.
   --------------------------------------------------------- */

/// Wie lange nach dem letzten Browser noch gewartet wird.
///
/// Die Erweiterung trennt und verbindet sich auch bei laufendem Browser (beim
/// Neuladen, nach Fehlern); die Frist verhindert ein Beenden und Neustarten
/// der Anwendung in diesen Fällen.
#[cfg(desktop)]
const NACHLAUF: std::time::Duration = std::time::Duration::from_secs(10);

/// Wartezeit, bis sich der Browser nach einem Start im Hintergrund meldet.
/// Danach beendet sich die Anwendung, damit keine unsichtbare Instanz
/// zurückbleibt.
#[cfg(desktop)]
const ERSTER_BROWSER: std::time::Duration = std::time::Duration::from_secs(30);

/// Beendet die Anwendung nach `warten`, wenn kein Browser verbunden und kein
/// Hauptfenster offen ist.
#[cfg(desktop)]
fn ohne_browser_beenden(warten: std::time::Duration) {
    std::thread::spawn(move || {
        std::thread::sleep(warten);
        if browser_verbunden() {
            return;
        }
        let Some(app) = crate::app_handle() else { return };
        let sichtbar = app
            .get_webview_window("main")
            .is_some_and(|w| w.is_visible().unwrap_or(true));
        if !sichtbar {
            app.exit(0);
        }
    });
}

/// Start im Hintergrund ohne Hauptfenster (das als Webansicht gut 100 MB
/// belegt). Rückfragen und Entsperren laufen über das kleine Fenster; das
/// Hauptfenster entsteht erst beim Öffnen von WKeePass
/// ([`crate::hauptfenster_zeigen`]).
#[cfg(desktop)]
pub fn hintergrund_start(window: tauri::WebviewWindow) {
    let _ = window.destroy();
    ohne_browser_beenden(ERSTER_BROWSER);
}

/// Ob die Anwendung beim Schließen des letzten Fensters enden darf.
///
/// Das ist nicht der Fall, solange ein Browser verbunden ist, und kurz nach
/// einem Start im Hintergrund, bevor sich der Browser gemeldet hat
/// ([`ohne_browser_beenden`] räumt dann auf).
#[cfg(desktop)]
pub fn ohne_fenster_weiter() -> bool {
    browser_verbunden() || route::im_hintergrund()
}

/// Schließen des Hauptfensters.
///
/// Ist ein Browser verbunden, wird nur das Fenster samt Webansicht
/// geschlossen. Sonst endet die Anwendung, auch wenn noch ein verstecktes
/// Rückfragefenster existiert.
#[cfg(desktop)]
pub fn hauptfenster(window: &tauri::WebviewWindow) {
    let app = window.app_handle().clone();
    window.on_window_event(move |event| {
        if let tauri::WindowEvent::CloseRequested { .. } = event {
            if !browser_verbunden() {
                app.exit(0);
            }
        }
    });
}

/// Sagt allen verbundenen Browsern, dass die Datenbank zu oder offen ist.
///
/// Beim Sperren endet die Schonfrist. Beim Entsperren beginnt sie, da
/// Master-Passwort, PIN oder Fingerabdruck einen stärkeren Nachweis darstellen
/// als die Rückfrage. Die Dauer steht in `browser.graceSeconds`; bei 0 wird
/// jedes Mal gefragt.
pub fn announce(locked: bool) {
    if let Ok(mut at) = last_identified().lock() {
        *at = if locked { None } else { Some(std::time::Instant::now()) };
    }
    if let Ok(mut at) = last_confirmed().lock() {
        *at = None;
    }
    // Beim Sperren bleibt der Stand erhalten, siehe [`stand_fuer_erweiterung`].
    if !locked {
        // Stand beim Entsperren lesen, da die Erweiterung unmittelbar danach
        // anfragt.
        std::thread::spawn(|| {
            let Some(app) = crate::app_handle() else { return };
            if let Ok(vault) = app.state::<Vault>().lock() {
                if let Ok(db) = vault.database() {
                    stand_merken(db);
                }
            }
        });
    }
    let message = json!({ "action": if locked { "database-locked" } else { "database-unlocked" } });
    if let Ok(map) = listeners().lock() {
        for notify in map.values() {
            notify(&message);
        }
    }
}

/// Ob der Kanal eingehängt ist. Unter Windows lässt sich das nicht am Pfad
/// prüfen, da das Nachschlagen von `\\.\pipe\…` eine Verbindung aufbaut.
static LISTENING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/* ---------------------------------------------------------
   Windows: benannte Pipe
   ---------------------------------------------------------
   Dasselbe wie der Unix-Socket darunter, nur mit tokio: Eine Pipe mit
   einfachem Handle kann nicht gleichzeitig lesen und schreiben — ein
   wartendes `read` hielte jede Antwort fest. tokio öffnet sie überlappend,
   dann geht beides.
   --------------------------------------------------------- */
#[cfg(windows)]
mod pipe {
    use std::sync::{Arc, Mutex};

    use serde_json::Value;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, WriteHalf};
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

    use super::{route, trace, Connection};

    type Writer = Arc<tokio::sync::Mutex<WriteHalf<NamedPipeServer>>>;

    /// Eine Pipe-Instanz je Verbindung. Die nächste wird angelegt, bevor die
    /// verbundene weitergegeben wird, damit durchgehend eine Instanz besteht.
    fn create(first: bool) -> std::io::Result<NamedPipeServer> {
        ServerOptions::new()
            // Existiert die Pipe bereits (anderer Besitzer), wird nicht
            // gelauscht.
            .first_pipe_instance(first)
            // Nur lokale Verbindungen.
            .reject_remote_clients(true)
            .create(route::socket_path())
    }

    pub async fn listen(app: tauri::AppHandle) -> Result<(), String> {
        let name = route::socket_path();
        let mut server = create(true).map_err(|e| {
            format!("Kanal {} nicht belegbar (läuft WKeePass schon?): {e}", name.display())
        })?;
        super::LISTENING.store(true, std::sync::atomic::Ordering::Relaxed);

        loop {
            if server.connect().await.is_err() {
                // Der Browser hat sich vor der Annahme getrennt; Instanz neu
                // anlegen.
                server = create(false).map_err(|e| e.to_string())?;
                continue;
            }
            let connected = std::mem::replace(&mut server, create(false).map_err(|e| e.to_string())?);
            tauri::async_runtime::spawn(serve(app.clone(), connected));
        }
    }

    /// Wie `serve`, für den Unix-Socket.
    async fn serve(app: tauri::AppHandle, pipe: NamedPipeServer) {
        let (mut reader, writer) = tokio::io::split(pipe);
        let writer: Writer = Arc::new(tokio::sync::Mutex::new(writer));
        let connection = Arc::new(Mutex::new(Connection::new()));

        let melder = Arc::clone(&writer);
        let angemeldet = super::register(Box::new(move |message: &Value| {
            let writer = Arc::clone(&melder);
            let message = message.clone();
            tauri::async_runtime::spawn(async move {
                trace("←", &message);
                let _ = send(&writer, &message).await;
            });
        }));

        let mut buffer = vec![0u8; 64 * 1024];
        let mut incoming = crate::keepass_extension::JsonStream::new();

        loop {
            let read = match reader.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };

            for message in incoming.push(&buffer[..read]) {
                trace("→", &message);

                let action = message.get("action").and_then(Value::as_str).unwrap_or_default();
                if action == "change-public-keys" {
                    let answer = match connection.lock() {
                        Ok(mut c) => c.change_public_keys(&message),
                        Err(_) => break,
                    };
                    if send(&writer, &answer).await.is_err() {
                        super::unregister(angemeldet);
                        return;
                    }
                    continue;
                }

                let app = app.clone();
                let connection = Arc::clone(&connection);
                let writer = Arc::clone(&writer);
                tauri::async_runtime::spawn(async move {
                    // Die Bearbeitung kann lange auf den Nutzer warten und
                    // läuft daher nicht auf einem Thread der Laufzeit.
                    let answer = tauri::async_runtime::spawn_blocking(move || {
                        Connection::process(&connection, &app, &message)
                    })
                    .await;
                    if let Ok(answer) = answer {
                        trace("←", &answer);
                        let _ = send(&writer, &answer).await;
                    }
                });
            }
        }
        super::unregister(angemeldet);
    }

    async fn send(writer: &Writer, answer: &Value) -> std::io::Result<()> {
        let text = serde_json::to_vec(answer)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let mut writer = writer.lock().await;
        writer.write_all(&text).await?;
        writer.flush().await
    }
}

#[cfg(not(windows))]
fn listen(app: tauri::AppHandle) -> Result<(), String> {
    use std::os::unix::net::UnixListener;

    let path = route::socket_path();

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Verzeichnis {} nicht anlegbar: {e}", parent.display()))?;
    }

    // Ein Socket bleibt nach einem Absturz als Datei bestehen und wird vor
    // dem Anlegen entfernt. Ob er verwaist oder belegt ist, zeigt ein
    // Verbindungsversuch: Antwortet jemand, gehört der Socket einer anderen
    // laufenden Instanz und bleibt unangetastet.
    if path.exists() {
        if std::os::unix::net::UnixStream::connect(&path).is_ok() {
            return Err(format!(
                "Der Kanal {} gehört bereits einer laufenden Ausgabe von WKeePass.",
                path.display()
            ));
        }
        let _ = std::fs::remove_file(&path);
    }

    let listener = UnixListener::bind(&path)
        .map_err(|e| format!("Kanal {} nicht belegbar: {e}", path.display()))?;
    LISTENING.store(true, std::sync::atomic::Ordering::Relaxed);

    // Zugriff nur für den Benutzer selbst.
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let app = app.clone();
        std::thread::spawn(move || serve(app, stream));
    }

    Ok(())
}

/// Bedient eine einzelne Verbindung, bis der Browser sie schließt.
#[cfg(not(windows))]
fn serve(app: tauri::AppHandle, stream: std::os::unix::net::UnixStream) {
    use std::sync::Arc;

    // Verbindungszustand und Schreibseite werden geteilt.
    let connection = Arc::new(Mutex::new(Connection::new()));
    let writer = Arc::new(Mutex::new(match stream.try_clone() {
        Ok(clone) => clone,
        Err(_) => return,
    }));

    let melder = Arc::clone(&writer);
    let angemeldet = register(Box::new(move |message: &Value| {
        trace("←", message);
        let _ = send(&melder, message);
    }));

    let mut reader = stream;
    let mut buffer = [0u8; 64 * 1024];
    let mut incoming = super::JsonStream::new();

    loop {
        let Ok(read) = reader.read(&mut buffer) else { break };
        if read == 0 {
            break;
        }

        // Auf dem Kanal folgt JSON ohne Längenangabe (wie bei KeePassXC);
        // `JsonStream` trennt die Nachrichten.
        for message in incoming.push(&buffer[..read]) {
            trace("→", &message);

            // Der Schlüsseltausch läuft im Lese-Thread, da alle folgenden
            // Nachrichten von ihm abhängen.
            let action = message.get("action").and_then(Value::as_str).unwrap_or_default();
            if action == "change-public-keys" {
                let answer = connection.lock().map(|mut c| c.change_public_keys(&message));
                let Ok(answer) = answer else { break };
                if send(&writer, &answer).is_err() {
                    break;
                }
                continue;
            }

            // Alle weiteren Nachrichten laufen in eigenen Threads. Die
            // Erweiterung bricht nach `keepassClient.messageTimeout = 500` ms
            // ab; eine auf Bestätigung wartende Anfrage (`get-logins`) darf
            // die übrigen Nachrichten derselben Verbindung nicht aufhalten.
            let app = app.clone();
            let connection = Arc::clone(&connection);
            let writer = Arc::clone(&writer);

            std::thread::spawn(move || {
                let answer = Connection::process(&connection, &app, &message);
                trace("←", &answer);
                let _ = send(&writer, &answer);
            });
        }
    }

    unregister(angemeldet);
}

/// Schreibt eine Antwort in einem Stück, damit sich parallele Threads nicht
/// überlagern.
#[cfg(not(windows))]
fn send(
    writer: &std::sync::Arc<Mutex<std::os::unix::net::UnixStream>>,
    answer: &Value,
) -> std::io::Result<()> {
    let text = serde_json::to_vec(answer)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let mut stream = writer
        .lock()
        .map_err(|_| std::io::Error::other("Schreibseite blockiert"))?;

    stream.write_all(&text)?;
    stream.flush()
}

/// Ziel des Protokolls der Browser-Anbindung, oder `None`, wenn es aus ist.
///
/// Protokolliert wird nur Aktion, Feldnamen und Längen, keine Inhalte;
/// Klartextwerte gelangen nicht ins Protokoll. Das genügt, um die Reihenfolge
/// der Aktionen, ausbleibende Antworten und fehlende Felder zu erkennen.
///
/// `WKEEPASS_BROWSER_LOG=1` (bzw. `2`) schreibt auf stderr. Ohne Konsole oder
/// Umgebungsvariablen (Start durch den Browser) schaltet eine vorhandene
/// Datei `$XDG_RUNTIME_DIR/wkeepass-browser.log` das Protokoll ein (ab dem
/// nächsten Start).
fn protokoll() -> Option<&'static Mutex<Box<dyn std::io::Write + Send>>> {
    static ZIEL: std::sync::OnceLock<Option<Mutex<Box<dyn std::io::Write + Send>>>> = std::sync::OnceLock::new();
    ZIEL.get_or_init(|| {
        if std::env::var("WKEEPASS_BROWSER_LOG").is_ok_and(|v| v != "0") {
            return Some(Mutex::new(Box::new(std::io::stderr()) as Box<dyn std::io::Write + Send>));
        }
        let datei = std::path::PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR")?).join("wkeepass-browser.log");
        if !datei.is_file() {
            return None;
        }
        std::fs::OpenOptions::new()
            .append(true)
            .open(datei)
            .ok()
            .map(|f| Mutex::new(Box::new(f) as Box<dyn std::io::Write + Send>))
    })
    .as_ref()
}

/// Schreibt eine Zeile mit Uhrzeit (auf Millisekunden genau) ins Protokoll.
pub(crate) fn protokolliere(zeile: &str) {
    // Lokaler Import, da der obere nur außerhalb von Windows gilt.
    use std::io::Write as _;
    let Some(ziel) = protokoll() else { return };
    let jetzt = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() % 100_000_000)
        .unwrap_or_default();
    if let Ok(mut ziel) = ziel.lock() {
        let _ = writeln!(ziel, "{:>5}.{:03} [{}] {zeile}", jetzt / 1000 % 100_000, jetzt % 1000, std::process::id());
    }
}

fn trace(richtung: &str, message: &Value) {
    if protokoll().is_none() {
        return;
    }

    let action = message.get("action").and_then(Value::as_str).unwrap_or("—");

    let felder: Vec<String> = message
        .as_object()
        .map(|o| {
            o.iter()
                .filter(|(name, _)| name.as_str() != "action")
                .map(|(name, value)| match value.as_str() {
                    // Base64-Felder werden auf Gültigkeit geprüft (ungültige
                    // Zeichen oder Länge führen in der Erweiterung zu
                    // „invalid encoding").
                    Some(text) if matches!(name.as_str(), "message" | "nonce" | "publicKey") => {
                        format!("{name}[{}{}]", text.len(), if ist_base64(text) { "" } else { " UNGÜLTIG" })
                    }
                    // Fehler stehen im Klartext; sie stammen aus der eigenen
                    // Tabelle und enthalten nichts aus der Datenbank.
                    Some(text) if matches!(name.as_str(), "error" | "errorCode") => {
                        format!("{name}={text}")
                    }
                    Some(text) => format!("{name}[{}]", text.len()),
                    None => name.clone(),
                })
                .collect()
        })
        .unwrap_or_default();

    protokolliere(&format!("{richtung} {action}  {}", felder.join(" ")));

    // Stufe 2 zeigt den Umschlag im Klartext (Schlüsseltext und Nonce); der
    // Inhalt bleibt verschlüsselt.
    if std::env::var("WKEEPASS_BROWSER_LOG").is_ok_and(|v| v == "2") {
        protokolliere(&format!("  {}", serde_json::to_string(message).unwrap_or_default()));
    }
}

/// Prüft wie `nacl.util.decodeBase64`.
fn ist_base64(text: &str) -> bool {
    if text.is_empty() || text.len() % 4 != 0 {
        return false;
    }

    let rumpf = text.trim_end_matches('=');
    let padding = text.len() - rumpf.len();

    padding <= 2 && rumpf.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/')
}

/* =========================================================
   Eine Verbindung
   ========================================================= */

/// Der Zustand einer offenen Verbindung.
struct Connection {
    keys: KeyPair,
    session: Option<Session>,
    /// Der Name, unter dem sich dieser Browser verknüpft hat.
    client_id: Option<String>,
    /// Ob auf dieser Verbindung bereits selbständig ums Entsperren gebeten
    /// wurde, siehe [`Connection::beim_start_entsperren`].
    entsperren_angeboten: bool,
}

impl Connection {
    fn new() -> Self {
        Self { keys: KeyPair::generate(), session: None, client_id: None, entsperren_angeboten: false }
    }

    /// Bittet einmal je Verbindung von selbst ums Entsperren.
    ///
    /// Die Erweiterung fragt beim Browserstart per `get-databasehash` nach der
    /// Datenbank. Ist sie gesperrt, merkt sie sich „zu“ und fragt nicht weiter,
    /// bis im Menü „Verbinden“ gedrückt wird (`triggerUnlock`). Deshalb öffnet
    /// sich beim ersten Mal das kleine Fenster; nach dem Entsperren meldet
    /// [`announce`] es der Erweiterung, die dann die Daten abruft.
    ///
    /// Es geschieht nur einmal je Verbindung, damit ein „Abbrechen“ gilt und
    /// eine später gesperrte Datenbank nicht bei jedem Tab-Wechsel ein Fenster
    /// öffnet. Einschaltbar über `browser.unlockOnConnect` (Voreinstellung:
    /// aus).
    fn beim_start_entsperren(shared: &std::sync::Arc<Mutex<Self>>, app: &tauri::AppHandle) {
        if offen_schnell(app) {
            return;
        }
        let erstes_mal = match shared.lock() {
            Ok(mut conn) => !std::mem::replace(&mut conn.entsperren_angeboten, true),
            Err(_) => false,
        };
        let erwuenscht = crate::settings::value(app, "browser.unlockOnConnect")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        protokolliere(&format!("Entsperren beim Verbinden: erstes Mal {erstes_mal}, erwünscht {erwuenscht}"));
        if erstes_mal && erwuenscht {
            let app = app.clone();
            std::thread::spawn(move || {
                let _ = await_unlocked(&app);
            });
        }
    }

    /// Nimmt eine Nachricht entgegen und liefert die Antwort.
    ///
    /// Läuft in einem eigenen Thread. Die Sperre auf der Verbindung wird nur
    /// zum Entschlüsseln und zum Verpacken gehalten; die Bearbeitung dazwischen
    /// blockiert andere Nachrichten derselben Verbindung nicht.
    fn process(
        shared: &std::sync::Arc<Mutex<Self>>,
        app: &tauri::AppHandle,
        message: &Value,
    ) -> Value {
        let action = message.get("action").and_then(Value::as_str).unwrap_or_default();

        // `triggerUnlock` steht außen an der Nachricht, nicht im verschlüsselten
        // Teil. Die Erweiterung setzt es auf Anstoß des Nutzers, etwa über
        // „Datenbank entsperren" im Menü.
        //
        // Hier wird nicht gewartet, da `get-databasehash` in der Erweiterung
        // eine kurze Frist hat (sonst „5: Verbindung nicht möglich"). Die
        // Anmeldemaske öffnet in einem eigenen Thread, die Nachricht wird
        // sofort beantwortet.
        if message.get("triggerUnlock").and_then(Value::as_str) == Some("true") && !offen_schnell(app) {
            entsperren_erbeten_merken();
            let app = app.clone();
            std::thread::spawn(move || {
                let _ = await_unlocked(&app);
            });
        }

        // Kurz sperren: entschlüsseln.
        let inner = {
            let Ok(conn) = shared.lock() else {
                return error(action, code::CANNOT_DECRYPT_MESSAGE, "Verbindung blockiert.");
            };

            let Some(session) = conn.session.as_ref() else {
                return error(action, code::CANNOT_DECRYPT_MESSAGE, "Kein Schlüsselaustausch erfolgt.");
            };

            let (Some(payload), Some(nonce_text)) = (
                message.get("message").and_then(Value::as_str),
                message.get("nonce").and_then(Value::as_str),
            ) else {
                return error(action, code::EMPTY_MESSAGE_RECEIVED, "Nachricht unvollständig.");
            };

            let nonce = match protocol::decode_nonce(nonce_text) {
                Ok(nonce) => nonce,
                Err(err) => return error(action, code::CANNOT_DECRYPT_MESSAGE, &err),
            };

            let plain = match session.open(payload, &nonce) {
                Ok(plain) => plain,
                Err(_) => {
                    return error(action, code::CANNOT_DECRYPT_MESSAGE, "Nachricht nicht entschlüsselbar.")
                }
            };

            match serde_json::from_slice::<Value>(&plain) {
                Ok(value) => (value, nonce),
                Err(_) => return error(action, code::CANNOT_DECRYPT_MESSAGE, "Inhalt nicht lesbar."),
            }
        };
        let (inner, nonce) = inner;

        // Ohne Sperre: die eigentliche Bearbeitung, die warten darf.
        let begonnen = std::time::Instant::now();
        let result = Self::dispatch(shared, app, action, &inner);
        // Protokolliert werden nur Aktion, Dauer und der eigene Fehlertext,
        // nichts aus der Datenbank.
        protokolliere(&match &result {
            Ok(_) => format!("= {action} ok ({} ms)", begonnen.elapsed().as_millis()),
            Err(Failure(code, text)) => format!("= {action} Fehler {code}: {text} ({} ms)", begonnen.elapsed().as_millis()),
        });

        // Kurz sperren: verpacken.
        let Ok(conn) = shared.lock() else {
            return error(action, code::CANNOT_DECRYPT_MESSAGE, "Verbindung blockiert.");
        };

        match result {
            Ok(mut answer) => {
                answer["action"] = json!(action);
                answer["version"] = json!(PROTOCOL_VERSION);
                answer["success"] = json!("true");
                conn.wrap(action, &answer, &nonce)
            }
            Err(err) => error(action, err.0, &err.1),
        }
    }

    /// Verpackt eine Antwort mit dem erhöhten Nonce der Anfrage; die
    /// Erweiterung zählt selbst hoch und vergleicht.
    fn wrap(&self, action: &str, answer: &Value, request_nonce: &Nonce) -> Value {
        let Some(session) = self.session.as_ref() else {
            return error(action, code::CANNOT_DECRYPT_MESSAGE, "Kein Schlüsselaustausch erfolgt.");
        };

        let reply_nonce = protocol::increment_nonce(request_nonce);
        let reply_nonce_b64 = protocol::encode(&reply_nonce);

        // Das Nonce steht auch im verschlüsselten Inhalt, da die Erweiterung
        // es dort erneut prüft:
        //
        //     verifyDatabaseResponse(response, nonce) {
        //         if (!checkNonceLength(response.nonce)) …
        //         if (response.nonce !== nonce) …
        //
        //     checkNonceLength(nonce) {
        //         return nacl.util.decodeBase64(nonce).length === 24;
        //
        // Innen und außen muss dasselbe Nonce stehen.
        let mut answer = answer.clone();
        answer["nonce"] = json!(reply_nonce_b64);

        let Ok(text) = serde_json::to_vec(&answer) else {
            return error(action, code::CANNOT_DECRYPT_MESSAGE, "Antwort nicht darstellbar.");
        };

        match session.seal(&text, &reply_nonce) {
            Ok(sealed) => json!({
                "action": action,
                "message": sealed,
                "nonce": protocol::encode(&reply_nonce),
            }),
            Err(err) => error(action, code::CANNOT_DECRYPT_MESSAGE, &err),
        }
    }

    fn change_public_keys(&mut self, message: &Value) -> Value {
        let Some(theirs) = message.get("publicKey").and_then(Value::as_str) else {
            return error("change-public-keys", code::CANNOT_DECRYPT_MESSAGE, "Kein öffentlicher Schlüssel.");
        };

        // Auch ohne Verschlüsselung gilt das erhöhte Nonce; die Erweiterung
        // prüft in `verifyKeyResponse` gegen `incrementedNonce`:
        //
        //     const reply = (response.nonce === nonce);
        let Some(nonce_text) = message.get("nonce").and_then(Value::as_str) else {
            return error("change-public-keys", code::CANNOT_DECRYPT_MESSAGE, "Kein Nonce.");
        };
        let nonce = match protocol::decode_nonce(nonce_text) {
            Ok(nonce) => nonce,
            Err(err) => return error("change-public-keys", code::CANNOT_DECRYPT_MESSAGE, &err),
        };

        match Session::new(&self.keys, theirs) {
            Ok(session) => {
                self.session = Some(session);
                json!({
                    "action": "change-public-keys",
                    "version": PROTOCOL_VERSION,
                    "publicKey": self.keys.public_base64(),
                    "success": "true",
                    "nonce": protocol::encode(&protocol::increment_nonce(&nonce)),
                })
            }
            Err(err) => error("change-public-keys", code::CANNOT_DECRYPT_MESSAGE, &err),
        }
    }

    /// Verteilt auf die einzelnen Aktionen.
    fn dispatch(
        shared: &std::sync::Arc<Mutex<Self>>,
        app: &tauri::AppHandle,
        action: &str,
        inner: &Value,
    ) -> Result<Value, Failure> {
        match action {
            // Ohne offene Datenbank beantwortbar:
            "get-databasehash" => {
                Self::beim_start_entsperren(shared, app);
                Ok(json!({ "hash": database_hash(app)? }))
            }
            "generate-password" => Ok(json!({
                "password": generate_password(),
                // Ältere Fassungen der Erweiterung lesen aus `entries`.
                "entries": [{ "login": "", "password": generate_password() }],
            })),

            // Wiedererkennung. Das Verknüpfen schreibt in die Datenbank; bei
            // gesperrter Datenbank wird der gemerkte Stand genannt.
            "associate" => {
                await_unlocked(app)?;
                Self::associate(shared, app, inner)
            }
            "test-associate" => Self::test_associate(shared, app, inner),

            // Kein Entsperrfenster für eine bereits gesperrte Datenbank.
            "lock-database" if !offen_schnell(app) => Ok(json!({})),

            // Die Erweiterung fragt beim Laden einer Seite mit Anmeldeformular
            // selbständig an. Bei gesperrter Datenbank öffnet sich ein Fenster
            // nur, wenn sie ums Entsperren gebeten hat, siehe
            // [`stand_fuer_erweiterung`].
            "get-logins" if !offen_schnell(app) && !entsperren_erbeten() => {
                Err(Failure(code::DATABASE_NOT_OPENED, "Datenbank ist zu.".into()))
            }

            // Alles Weitere setzt eine offene Datenbank voraus. Ist sie
            // gesperrt, wird gewartet statt abgewiesen.
            _ => {
                await_unlocked(app)?;

                match action {
                    "get-logins" => Self::get_logins(shared, app, inner),
                    "set-login" => set_login(app, inner),
                    "get-totp" => get_totp(app, inner, client_id(shared)),
                    "lock-database" => lock_database(app),
                    "get-database-groups" => database_groups(app),
                    "create-new-group" => create_group(app, inner),
                    "delete-entry" => delete_entry(app, inner),
                    "passkeys-register" => Self::passkeys_register(shared, app, inner),
                    "passkeys-get" => Self::passkeys_get(shared, app, inner),
                    other => Err(Failure(code::INCORRECT_ACTION, format!("Aktion „{other}“ ist nicht angebunden."))),
                }
            }
        }
    }

    /* ---------- Zugangsdaten ---------- */

    /// Sucht passende Einträge — **nach Rückfrage beim Nutzer**.
    ///
    /// Die Rückfrage verhindert, dass beliebige Websites über die Erweiterung
    /// Zugangsdaten abrufen. Der Dialog wird vom eigenen Fenster gezeichnet,
    /// da eine Seite die Darstellung im Browser beeinflussen könnte.
    fn get_logins(shared: &std::sync::Arc<Mutex<Self>>, app: &tauri::AppHandle, inner: &Value) -> Result<Value, Failure> {
        let url = inner
            .get("url")
            .and_then(Value::as_str)
            .ok_or_else(|| Failure(code::NO_URL_PROVIDED, "Keine Adresse angegeben.".into()))?;

        // Ziel des Formulars; weicht es von der besuchten Adresse ab, wird es
        // in der Rückfrage angezeigt.
        let submit = inner.get("submitUrl").and_then(Value::as_str);

        let (host, path) = split_url(url)
            .ok_or_else(|| Failure(code::NO_URL_PROVIDED, "Adresse nicht lesbar.".into()))?;
        let client = client_id(shared);

        let candidates = matching_entries(app, &host, &path)?;
        if candidates.is_empty() {
            return Ok(json!({ "count": 0, "entries": [] }));
        }

        // Ein ausdrückliches Nein am Eintrag gilt. Solche Vermerke stammen aus
        // KeePassXC und werden hier nicht mehr angelegt.
        let offen: Vec<&Candidate> = candidates.iter().filter(|c| c.decision != Some(false)).collect();
        if offen.is_empty() {
            return Ok(json!({ "count": 0, "entries": [] }));
        }

        let answer = ask_user(
            app,
            json!({
                "kind": "logins",
                "client": client,
                "url": url,
                "host": host,
                "submitUrl": submit,
                "mismatch": submit.and_then(|u| split_url(u).map(|(h, _)| h)).is_some_and(|s| s != host),
                "entries": offen.iter().map(|c| json!({
                    "uuid": c.uuid,
                    "name": c.title,
                    "login": c.username,
                    "group": c.group,
                })).collect::<Vec<_>>(),
            }),
        )?;

        if !answer.allow {
            return Err(Failure(code::ACTION_CANCELLED_OR_DENIED, "Zugriff abgelehnt.".into()));
        }

        // Für „Zuletzt genutzt": Der Kern meldet die herausgegebenen Einträge,
        // die Oberfläche zählt.
        let _ = app.emit("entries-used", offen.iter().map(|c| c.uuid.clone()).collect::<Vec<_>>());
        // Die Seite ist erreichbar; ihr Icon wird abgerufen.
        crate::favicon::im_hintergrund(app, offen.iter().map(|c| c.uuid.clone()).collect(), false);

        let entries: Vec<Value> = offen
            .iter()
            .map(|c| {
                json!({
                    "login": c.username,
                    "name": c.title,
                    "password": c.password,
                    "uuid": c.uuid,
                    "group": c.group,
                    "totp": c.totp,
                })
            })
            .collect();

        Ok(json!({
            "count": entries.len(),
            "entries": entries,
            "hash": database_hash(app)?,
            "id": client,
        }))
    }

    /* ---------- Passkeys ---------- */

    /// Legt einen Passkey an — nach Rückfrage.
    fn passkeys_register(shared: &std::sync::Arc<Mutex<Self>>, app: &tauri::AppHandle, inner: &Value) -> Result<Value, Failure> {
        let options = inner
            .get("publicKey")
            .ok_or_else(|| Failure(code::PASSKEYS_EMPTY_PUBLIC_KEY, "Keine Angaben zum Passkey.".into()))?;

        // Fehlt `rp.id`, gilt nach WebAuthn der Rechnername der Seite, nicht
        // `rp.name` (der Anzeigename).
        let rp_id = options
            .get("rp")
            .and_then(|rp| rp.get("id"))
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .or_else(|| inner.get("origin").and_then(Value::as_str).and_then(host_of_str))
            .ok_or_else(|| Failure(code::PASSKEYS_UNKNOWN_ERROR, "Kein Ziel angegeben.".into()))?
            .to_string();

        let user = options.get("user");
        let name = user
            .and_then(|u| u.get("name"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();

        let answer = ask_user_mindestens(
            app,
            json!({
                "kind": "passkey-register",
                "client": client_id(shared),
                "host": rp_id,
                "login": name,
            }),
            Guard::Identify,
        )?;
        if !answer.allow {
            return Err(Failure(code::PASSKEYS_REQUEST_CANCELED, "Anlegen abgelehnt.".into()));
        }

        let request = crate::passkey::CreateRequest {
            rp_id: rp_id.clone(),
            user_name: name,
            user_display_name: user
                .and_then(|u| u.get("displayName"))
                .and_then(Value::as_str)
                .map(str::to_string),
            challenge: options
                .get("challenge")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            user_handle: user
                .and_then(|u| u.get("id"))
                .and_then(Value::as_str)
                .map(str::to_string),
            origin: inner.get("origin").and_then(Value::as_str).map(str::to_string),
        };

        let created = crate::passkey::passkey_create(app.state::<Vault>(), request)
            .map_err(|e| Failure(code::PASSKEYS_UNKNOWN_ERROR, e))?;

        persist(app);
        Ok(json!({ "response": credential(&created.credential_id, json!({
            "attestationObject": created.attestation_object,
            "clientDataJSON": created.client_data_json,
            "clientExtensionResults": {},
        })) }))
    }

    /// Meldet mit einem vorhandenen Passkey an — nach Rückfrage.
    fn passkeys_get(shared: &std::sync::Arc<Mutex<Self>>, app: &tauri::AppHandle, inner: &Value) -> Result<Value, Failure> {
        let options = inner
            .get("publicKey")
            .ok_or_else(|| Failure(code::PASSKEYS_EMPTY_PUBLIC_KEY, "Keine Angaben zur Anmeldung.".into()))?;

        let rp_id = options
            .get("rpId")
            .and_then(Value::as_str)
            .or_else(|| inner.get("origin").and_then(Value::as_str).and_then(host_of_str))
            .ok_or_else(|| Failure(code::PASSKEYS_UNKNOWN_ERROR, "Kein Ziel angegeben.".into()))?
            .to_string();

        let answer = ask_user_mindestens(
            app,
            json!({
                "kind": "passkey-get",
                "client": client_id(shared),
                "host": rp_id,
            }),
            Guard::Identify,
        )?;
        if !answer.allow {
            return Err(Failure(code::PASSKEYS_REQUEST_CANCELED, "Anmeldung abgelehnt.".into()));
        }

        // Die Seite kann mehrere Kennungen anbieten (etwa Telefon und Rechner);
        // es werden alle geprüft. Eine leere Liste bedeutet „beliebiger
        // Schlüssel“; dann wird allein über die Gegenstelle gesucht.
        let angeboten: Vec<String> = options
            .get("allowCredentials")
            .and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .filter_map(|c| c.get("id").and_then(Value::as_str))
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();

        let challenge = options
            .get("challenge")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let origin = inner.get("origin").and_then(Value::as_str).map(str::to_string);

        let mut versuche = angeboten.into_iter().map(Some).collect::<Vec<_>>();
        if versuche.is_empty() {
            versuche.push(None);
        }

        let mut letzter = String::from("Für diese Gegenstelle ist kein Passkey hinterlegt.");
        let mut gefunden = None;

        for kennung in versuche {
            match crate::passkey::passkey_assert(
                app.state::<Vault>(),
                rp_id.clone(),
                challenge.clone(),
                kennung,
                origin.clone(),
            ) {
                Ok(antwort) => {
                    gefunden = Some(antwort);
                    break;
                }
                Err(err) => letzter = err,
            }
        }

        let asserted = gefunden.ok_or(letzter)
        .map_err(|e| Failure(code::PASSKEYS_UNKNOWN_ERROR, e))?;
        let _ = app.emit("entries-used", [&asserted.entry_uuid]);

        Ok(json!({ "response": credential(&asserted.credential_id, json!({
            "clientDataJSON": asserted.client_data_json,
            "authenticatorData": asserted.authenticator_data,
            "signature": asserted.signature,
            "userHandle": asserted.user_handle,
            "clientExtensionResults": {},
        })) }))
    }

    /* ---------- Verknüpfen ---------- */

    /// Merkt sich diesen Browser dauerhaft in der Datenbank.
    ///
    /// Der übergebene Schlüssel ist nicht der Sitzungsschlüssel, sondern dient
    /// der Wiedererkennung.
    fn associate(shared: &std::sync::Arc<Mutex<Self>>, app: &tauri::AppHandle, inner: &Value) -> Result<Value, Failure> {
        let key = inner
            .get("idKey")
            .and_then(Value::as_str)
            .ok_or_else(|| Failure(code::ASSOCIATION_FAILED, "Kein Verknüpfungsschlüssel.".into()))?;

        // Vorläufiger Name; eine Rückfrage zur Namensvergabe ist nicht
        // implementiert.
        let name = inner
            .get("key")
            .and_then(Value::as_str)
            .map(|_| format!("WKeePass {}", short(key)))
            .unwrap_or_else(|| format!("Browser {}", short(key)));

        let state = app.state::<Vault>();
        let mut vault = state.lock().map_err(|_| Failure(0, "Kern blockiert.".into()))?;
        let db = vault.database_mut().map_err(|_| Failure(code::DATABASE_NOT_OPENED, "Datenbank ist zu.".into()))?;

        // Ist der Schlüssel bekannt, bleibt die vorhandene Verknüpfung
        // bestehen.
        if let Some(bekannt) = association_with_key(db, key) {
            protokolliere(&format!("associate: Schlüssel schon bekannt als „{bekannt}“"));
            if let Ok(mut conn) = shared.lock() {
                conn.client_id = Some(bekannt.clone());
            }
            return Ok(json!({ "id": bekannt, "hash": database_hash_locked(db) }));
        }

        db.meta.custom_data.insert(
            format!("{ASSOCIATION_PREFIX}{name}"),
            keepass::db::CustomDataItem {
                value: Some(keepass::db::CustomDataValue::String(key.to_string())),
                // Mit Zeitpunkt; beim Zusammenführen gilt die jüngere Fassung.
                last_modification_time: Some(keepass::db::Times::now()),
            },
        );

        if let Ok(mut conn) = shared.lock() {
            conn.client_id = Some(name.clone());
        }

        protokolliere(&format!("associate: neu als „{name}“"));
        let antwort = json!({ "id": name, "hash": database_hash_locked(db) });
        stand_merken(db);
        persist(app);
        Ok(antwort)
    }

    /// Prüft, ob dieser Browser schon bekannt ist.
    fn test_associate(shared: &std::sync::Arc<Mutex<Self>>, app: &tauri::AppHandle, inner: &Value) -> Result<Value, Failure> {
        let (Some(id), Some(key)) = (
            inner.get("id").and_then(Value::as_str),
            inner.get("key").and_then(Value::as_str),
        ) else {
            return Err(Failure(code::ASSOCIATION_FAILED, "Angaben unvollständig.".into()));
        };

        // Nicht auf einen beschäftigten Tresor warten, siehe [`stand`].
        let stand = stand_fuer_erweiterung(app)?;

        if stand.schluessel.get(id).map(String::as_str) != Some(key) {
            // Ins Protokoll nur Namen, keine Schlüssel.
            let mut bekannt: Vec<&str> = stand.schluessel.keys().map(String::as_str).collect();
            bekannt.sort_unstable();
            protokolliere(&format!(
                "test-associate: gefragt „{id}“ ({}), in der Datenbank: {bekannt:?}",
                if stand.schluessel.contains_key(id) { "Name bekannt, Schlüssel anders" } else { "Name unbekannt" }
            ));
            return Err(Failure(code::ASSOCIATION_FAILED, "Dieser Browser ist nicht verknüpft.".into()));
        }

        if let Ok(mut conn) = shared.lock() {
            conn.client_id = Some(id.to_string());
        }
        Ok(json!({ "id": id, "hash": stand.hash }))
    }
}

/// Unter welchem Namen dieser Schlüssel schon verknüpft ist.
fn association_with_key(db: &keepass::Database, key: &str) -> Option<String> {
    db.meta.custom_data.iter().find_map(|(name, item)| {
        let rest = name.strip_prefix(ASSOCIATION_PREFIX)?;
        (als_text(item.value.as_ref()?) == key).then(|| rest.to_string())
    })
}

/// Der Wert einer Zusatzangabe als Text.
///
/// Die Bibliothek liest Werte, die sich als Base64 lesen lassen (auch
/// „true“), beim Einlesen als `Binary`. Zurückkodiert ergibt das den
/// gespeicherten Text, da nur Base64 in seiner einzigen gültigen Schreibweise
/// als `Binary` gilt.
fn als_text(wert: &keepass::db::CustomDataValue) -> std::borrow::Cow<'_, str> {
    use base64::Engine as _;
    match wert {
        keepass::db::CustomDataValue::String(text) => text.into(),
        keepass::db::CustomDataValue::Binary(bytes) => base64::engine::general_purpose::STANDARD.encode(bytes).into(),
    }
}

/// Baut die Hülle, die die Erweiterung um einen Passkey erwartet.
///
/// Ablauf in der Erweiterung:
///
/// ```javascript
/// sendPasskeysResponse(ret.response, …)          // passkeys-inject.js
/// … = { publicKey: publicKey, fallback: … }      // passkeys-utils.js
/// createPublicKeyCredential(response.publicKey)  // passkeys.js
/// ```
///
/// Die Erweiterung legt die Hülle `publicKey` selbst an; der Parameter ist
/// bereits der fertige Ausweis. Die Antwort enthält daher genau eine Stufe:
///
/// ```text
/// { "response": {                    ← liest passkeys-inject.js als ret.response
///     "id", "type", "authenticatorAttachment",
///     "response": { … }              ← die eigentlichen WebAuthn-Daten
///   } }
/// ```
///
/// `rawId` entfällt, die Erweiterung berechnet es aus `id`.
/// `authenticatorAttachment: "platform"` kennzeichnet einen Schlüssel auf
/// diesem Gerät (hier: in der Datenbank).
fn credential(id: &str, response: Value) -> Value {
    json!({
        "id": id,
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "response": response,
    })
}

/* =========================================================
   Zurückschreiben
   ========================================================= */

/// Schreibt die Datenbank zurück, nachdem die Erweiterung etwas geändert hat.
///
/// Läuft in einem eigenen Thread: Zum Speichern wird der Schlüssel neu aus
/// dem Master-Passwort abgeleitet, was mit Argon2 knapp eine Sekunde dauert,
/// die Erweiterung aber nach 500 ms abbricht. Die Antwort erfolgt daher vor
/// dem Speichern.
///
/// Der Thread nimmt die Sperre selbst und wartet, bis der Aufrufer seine
/// freigegeben hat.
fn persist(app: &tauri::AppHandle) {
    let app = app.clone();
    std::thread::spawn(move || {
        let ergebnis = crate::database::commit(&app, &app.state::<Vault>());
        protokolliere(&match &ergebnis {
            Ok(_) => "Gespeichert".to_string(),
            Err(err) => format!("NICHT gespeichert: {err}"),
        });
        match ergebnis {
            // Das Hauptfenster aktualisiert seine Anzeige.
            Ok(_) => {
                let _ = app.emit("browser-saved", ());
            }
            Err(err) => {
                // Der Fehler bedeutet verlorene Änderungen und wird daher
                // unabhängig von `WKEEPASS_BROWSER_LOG` ausgegeben.
                eprintln!("[Browser] Nicht gespeichert: {err}");
                let _ = app.emit("browser-save-failed", err);
            }
        }
    });
}

/// Wie sich dieser Browser verknüpft hat — für die Anzeige in der Rückfrage.
fn client_id(shared: &std::sync::Arc<Mutex<Connection>>) -> String {
    shared
        .lock()
        .ok()
        .and_then(|c| c.client_id.clone())
        .unwrap_or_else(|| "Browser".into())
}

/* =========================================================
   Kleinkram
   ========================================================= */

/// Fehlernummer und Text, wie die Erweiterung sie erwartet.
struct Failure(u16, String);

fn error(action: &str, code: u16, text: &str) -> Value {
    json!({
        "action": action,
        "errorCode": code.to_string(),
        "error": text,
        "success": "false",
    })
}

/// Ein kurzer, lesbarer Anfang eines Schlüssels für Anzeigenamen.
fn short(key: &str) -> String {
    key.chars().filter(|c| c.is_alphanumeric()).take(6).collect()
}

/// Kennzeichnet die offene Datenbank.
///
/// Die Erweiterung erkennt daran, ob dieselbe Datei offen ist wie zuvor. Der
/// Wert muss stabil sein und sich zwischen Datenbanken unterscheiden.
fn database_hash(app: &tauri::AppHandle) -> Result<String, Failure> {
    stand_fuer_erweiterung(app).map(|stand| stand.hash)
}

/// Liefert der Erweiterung den Stand zur Wiedererkennung (offen, beschäftigt
/// oder gesperrt).
///
/// Bei gesperrter Datenbank antwortet die Funktion aus dem zuletzt gesehenen
/// Stand, als wäre die Datenbank offen. Die Erweiterung fragt vor einem
/// Passkey `get-databasehash` ohne `triggerUnlock`
/// (`testAssociation(tab, [ false ])` in `passkeysGet`/`passkeysRegister`)
/// und bricht bei der Antwort „zu“ ab. So erreicht `passkeys-get` den Kern,
/// und das kleine Fenster bittet in [`Connection::dispatch`] ums Entsperren.
///
/// Damit nicht jede Seite mit Anmeldeformular das Fenster öffnet, gibt
/// `get-logins` bei gesperrter Datenbank sofort „zu“ zurück, außer die
/// Erweiterung hat ums Entsperren gebeten (Klick aufs Symbol im Feld,
/// Tastenkürzel), siehe [`entsperren_erbeten`].
///
/// Preisgegeben werden nur die Kennung der Datenbank und ein Ja/Nein zum
/// Schlüssel, den der Browser selbst mitbringt.
fn stand_fuer_erweiterung(app: &tauri::AppHandle) -> Result<Stand, Failure> {
    if let Some(vault) = tresor_kurz(app) {
        if let Ok(db) = vault.database() {
            return Ok(stand_merken(db));
        }
    }
    stand_zuletzt().ok_or_else(|| Failure(code::DATABASE_NOT_OPENED, "Datenbank ist zu.".into()))
}

/* ---------------------------------------------------------
   Antworten, die nicht warten dürfen
   ---------------------------------------------------------
   `get-databasehash` und `test-associate` stellt die Erweiterung mit einer
   Frist von 500 ms. Bleibt die Antwort auf `test-associate` aus, **löscht**
   sie ihre gespeicherte Verknüpfung — danach heißt es „nicht konfiguriert“,
   man muss neu verbinden, und jedes Mal kam ein weiterer „WKeePass …“ in
   ihre Liste.

   Speichern hält den Tresor aber Sekunden: Datei lesen, zusammenführen,
   mit Argon2 neu verschlüsseln. Kam die Frage genau dann — etwa gleich nach
   dem Entsperren, wenn Zuletzt-genutzt und Symbole geschrieben werden —,
   war die Verknüpfung weg.

   Deshalb: höchstens kurz auf den Tresor warten, sonst aus dem zuletzt
   gesehenen Stand antworten. Der Stand ist nur, was ohnehin über die
   Leitung ginge — Kennung der Datenbank und die Schlüssel der verknüpften
   Browser —, und er gilt auch gesperrt (siehe `stand_fuer_erweiterung`).
   --------------------------------------------------------- */

/// Was die Erweiterung zur Wiedererkennung braucht.
#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct Stand {
    hash: String,
    /// Name der Verknüpfung → Schlüssel.
    schluessel: std::collections::HashMap<String, String>,
}

fn stand() -> &'static Mutex<Option<Stand>> {
    static STAND: Mutex<Option<Stand>> = Mutex::new(None);
    &STAND
}

/// Liest den Stand aus der offenen Datenbank und merkt ihn sich.
fn stand_merken(db: &keepass::Database) -> Stand {
    let schluessel = db
        .meta
        .custom_data
        .iter()
        .filter_map(|(name, item)| {
            let id = name.strip_prefix(ASSOCIATION_PREFIX)?;
            Some((id.to_string(), als_text(item.value.as_ref()?).into_owned()))
        })
        .collect();
    let neu = Stand { hash: database_hash_locked(db), schluessel };
    let geaendert = match stand().lock() {
        Ok(mut s) => {
            let geaendert = s.as_ref() != Some(&neu);
            *s = Some(neu.clone());
            geaendert
        }
        Err(_) => false,
    };
    if geaendert {
        stand_sichern(&neu);
    }
    neu
}

/// Der zuletzt gesehene Stand, auch nach dem Sperren und (aus der Datei) nach
/// einem Neustart ohne Entsperren, siehe [`stand_fuer_erweiterung`].
fn stand_zuletzt() -> Option<Stand> {
    let mut s = stand().lock().ok()?;
    if s.is_none() {
        *s = stand_laden();
    }
    s.clone()
}

/// Wo der Stand zwischen zwei Starts liegt: neben `settings.json`.
///
/// Enthalten sind nur die Kennung der Datenbank und die öffentlichen
/// Schlüssel der Erweiterung zur Wiedererkennung, keine Passwörter.
fn stand_datei() -> Option<std::path::PathBuf> {
    let app = crate::app_handle()?;
    Some(app.path().app_config_dir().ok()?.join("browser-stand.json"))
}

fn stand_sichern(stand: &Stand) {
    let Some(datei) = stand_datei() else { return };
    let Ok(text) = serde_json::to_vec(stand) else { return };
    if let Some(ordner) = datei.parent() {
        let _ = std::fs::create_dir_all(ordner);
    }
    if let Err(err) = crate::util::write_atomic(&datei, &text) {
        protokolliere(&format!("Stand nicht gesichert: {err}"));
    }
}

fn stand_laden() -> Option<Stand> {
    serde_json::from_slice(&std::fs::read(stand_datei()?).ok()?).ok()
}

/// Verwirft den Stand (nur für Tests).
#[cfg(test)]
fn stand_vergessen() {
    if let Ok(mut s) = stand().lock() {
        *s = None;
    }
}

/// Höchste Wartezeit auf einen beschäftigten Tresor; lässt Spielraum zur
/// Frist der Erweiterung (500 ms) für Ver- und Entschlüsseln.
const KURZ: std::time::Duration = std::time::Duration::from_millis(300);

/// Der Tresor, wenn er binnen [`KURZ`] frei wird, sonst `None`.
fn tresor_kurz(app: &tauri::AppHandle) -> Option<std::sync::MutexGuard<'_, crate::state::VaultState>> {
    let tresor: &Vault = app.state::<Vault>().inner();
    let bis = std::time::Instant::now() + KURZ;
    loop {
        match tresor.try_lock() {
            Ok(vault) => return Some(vault),
            Err(std::sync::TryLockError::WouldBlock) if std::time::Instant::now() < bis => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(_) => return None,
        }
    }
}

/// Woran die Erweiterung diese Datenbank wiedererkennt.
///
/// Berechnet aus der Kennung des obersten Ordners, die unveränderlich ist
/// (wie bei KeePassXC). Der Name der Datenbank geht nicht ein, damit eine
/// Umbenennung die Verknüpfungen nicht ungültig macht.
fn database_hash_locked(db: &keepass::Database) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(db.root().id().uuid().to_string().as_bytes());

    hasher.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/* =========================================================
   Die Rückfrage beim Nutzer
   ---------------------------------------------------------
   Eine Anfrage aus dem Browser darf nie unbemerkt Zugangsdaten
   herausgeben. Der Faden, der die Verbindung bedient, wird deshalb
   angehalten: Die Anfrage wird geparkt, das Fenster bekommt ein Ereignis,
   und erst die Antwort des Nutzers weckt den Faden wieder.

   Bewusst so herum: Der Dialog gehört unserer Oberfläche. Was der Browser
   zeichnet, kann eine Website beeinflussen — eine Bestätigung, die dort
   entstünde, wäre wertlos.
   ========================================================= */

/// Wie lange auf eine Antwort gewartet wird, bevor sie als Ablehnung gilt.
const CONSENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Wie lange eine Legitimation nachwirkt, wenn nichts eingestellt ist.
///
/// Eine Minute: lang genug für einen zusammenhängenden Vorgang, kurz genug für
/// einen unbeaufsichtigten Rechner. Einstellbar über `browser.graceSeconds`
/// (0 = jedes Mal fragen); Sperren beendet die Frist sofort.
const IDENTIFY_GRACE_SECS: u64 = 60;

/// Die eingestellte Frist, höchstens eine Stunde (wie im Einstellungsfeld).
fn identify_grace(app: &tauri::AppHandle) -> std::time::Duration {
    let secs = crate::settings::value(app, "browser.graceSeconds")
        .and_then(|v| v.as_u64())
        .unwrap_or(IDENTIFY_GRACE_SECS)
        .min(3600);
    std::time::Duration::from_secs(secs)
}

/// Wann zuletzt erfolgreich legitimiert wurde.
fn last_identified() -> &'static Mutex<Option<std::time::Instant>> {
    static LAST: std::sync::OnceLock<Mutex<Option<std::time::Instant>>> = std::sync::OnceLock::new();
    LAST.get_or_init(|| Mutex::new(None))
}

/// Merkt sich eine erfolgreiche Legitimation. Ruft das Rückfragefenster auf.
#[tauri::command]
pub fn browser_identified() -> Result<bool, String> {
    *last_identified().lock().map_err(|_| "Blockiert.".to_string())? =
        Some(std::time::Instant::now());
    Ok(true)
}

/// Wann zuletzt nur per Knopfdruck bestätigt wurde (Stufe „Bestätigen“).
///
/// Getrennt vom Nachweis: Ein Klick belegt Anwesenheit, nicht Identität. Für
/// die Stufe „Bestätigen“ genügt das in der Schonfrist; ein Passkey verlangt
/// einen Nachweis.
fn last_confirmed() -> &'static Mutex<Option<std::time::Instant>> {
    static LAST: Mutex<Option<std::time::Instant>> = Mutex::new(None);
    &LAST
}

fn frisch(zeit: &Mutex<Option<std::time::Instant>>, frist: std::time::Duration) -> bool {
    zeit.lock().ok().and_then(|at| *at).is_some_and(|at| at.elapsed() < frist)
}

/// Ob die letzte Legitimation noch gültig ist. Bei `Identify` zählt nur ein
/// Nachweis, sonst auch ein Knopfdruck.
fn within_grace(app: &tauri::AppHandle, mode: Guard) -> bool {
    let frist = identify_grace(app);
    frisch(last_identified(), frist) || (mode != Guard::Identify && frisch(last_confirmed(), frist))
}

/// Wie lange auf das Entsperren gewartet wird.
const UNLOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);

/// Die Entscheidung des Nutzers.
pub struct Decision {
    pub allow: bool,
}

/// Eine geparkte Anfrage: der Rückkanal und das, was das Fenster zeigen soll.
struct Parked {
    tx: std::sync::mpsc::Sender<Decision>,
    details: Value,
}

type Pending = std::collections::HashMap<String, Parked>;

fn pending() -> &'static Mutex<Pending> {
    static PENDING: std::sync::OnceLock<Mutex<Pending>> = std::sync::OnceLock::new();
    PENDING.get_or_init(|| Mutex::new(Pending::new()))
}

/// Parkt die Anfrage und wartet auf die Antwort aus dem Fenster, mit der
/// unter `browser.guard` eingestellten Strenge.
fn ask_user(app: &tauri::AppHandle, details: Value) -> Result<Decision, Failure> {
    ask_user_mindestens(app, details, Guard::Never)
}

/// Wie [`ask_user`], aber mindestens mit der Stufe `mindestens`,
/// unabhängig von der Einstellung.
///
/// Passkeys verlangen immer einen Nachweis, da sie der Seite „Nutzer
/// geprüft“ (UV) melden. Die Schonfrist gilt dennoch.
fn ask_user_mindestens(app: &tauri::AppHandle, mut details: Value, mindestens: Guard) -> Result<Decision, Failure> {
    let mode = guard(app).max(mindestens);

    // Stufe „Nichts": kein Fenster, keine Frist, keine Verzögerung.
    if mode == Guard::Never {
        return Ok(Decision { allow: true });
    }

    // Innerhalb der Schonfrist wird nicht erneut gefragt (beide Stufen).
    // Die Prüfung erfolgt vor dem Eintragen, damit kein unbeantworteter
    // Eintrag in der Liste bleibt und das Rückfragefenster offen hält.
    if within_grace(app, mode) {
        return Ok(Decision { allow: true });
    }

    let id = neue_id();
    let (tx, rx) = std::sync::mpsc::channel();

    details["id"] = json!(id);
    // `Never` ist bereits behandelt; es bleiben die beiden Stufen, die das
    // Fenster darstellt.
    details["guard"] = json!(match mode {
        Guard::Identify => "identify",
        _ => "confirm",
    });

    pending()
        .lock()
        .map_err(|_| Failure(0, "Rückfrage blockiert.".into()))?
        .insert(id.clone(), Parked { tx, details: details.clone() });

    open_request_window(app, ASK_HEIGHT);

    // Das Ereignis erreicht das Fenster nur, wenn es seine Listener bereits
    // registriert hat; zusätzlich fragt die Seite beim Start selbst nach
    // (`browser_pending`).
    let _ = app.emit("browser-request", details);

    let answer = rx.recv_timeout(CONSENT_TIMEOUT);

    // Eintrag in jedem Fall entfernen, auch nach Zeitüberschreitung.
    unpark(app, &id);

    // Keine Antwort gilt als Nein.
    Ok(answer.unwrap_or(Decision { allow: false }))
}

/// Kennung einer geparkten Anfrage (Uhrzeit plus Zähler, damit Anfragen in
/// derselben Millisekunde unterscheidbar bleiben).
fn neue_id() -> String {
    static ZAEHLER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    format!("br{}-{}", now_millis(), ZAEHLER.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
}

/// Beantwortet eine geparkte Anfrage. Wird von der Oberfläche aufgerufen.
///
/// Die Antwort gilt für alle wartenden Anfragen derselben Art von derselben
/// Seite, da ein Formular mit mehreren Feldern oft mehrfach kurz nacheinander
/// anfragt.
///
/// Ein „Übernehmen“ ohne Nachweis (Stufe `confirm`) setzt die Schonfrist wie
/// ein Nachweis.
#[tauri::command]
pub fn browser_answer(id: String, allow: bool) -> Result<bool, String> {
    let Ok(mut map) = pending().lock() else {
        return Err("Rückfrage blockiert.".into());
    };

    let Some(parked) = map.remove(&id) else {
        // Bereits abgelaufen oder doppelt beantwortet; kein Fehler.
        return Ok(false);
    };

    let gleiche_frage = |d: &Value| {
        d.get("kind") == parked.details.get("kind") && d.get("host") == parked.details.get("host")
    };
    let geschwister: Vec<String> =
        map.iter().filter(|(_, p)| gleiche_frage(&p.details)).map(|(k, _)| k.clone()).collect();
    for k in geschwister {
        if let Some(p) = map.remove(&k) {
            let _ = p.tx.send(Decision { allow });
        }
    }
    let _ = parked.tx.send(Decision { allow });
    drop(map);

    if allow && parked.details.get("guard").and_then(Value::as_str) == Some("confirm") {
        if let Ok(mut at) = last_confirmed().lock() {
            *at = Some(std::time::Instant::now());
        }
    }
    Ok(true)
}

/// Was gerade auf eine Antwort wartet.
///
/// Das Rückfragefenster ruft das beim Start ab, da Ereignisse vor dem Laden
/// seiner Module verloren gehen.
#[tauri::command]
pub fn browser_pending() -> Result<Option<Value>, String> {
    let map = pending().lock().map_err(|_| "Rückfrage blockiert.".to_string())?;

    // Die älteste zuerst.
    Ok(map.values().map(|p| p.details.clone()).next())
}

/// Wartet, bis die Datenbank offen ist, und bittet darum.
///
/// Statt eines sofortigen Fehlers wird gewartet, da die Erweiterung sonst
/// abbricht und die Seite neu geladen werden müsste.
///
/// Gefragt wird im kleinen Fenster, nicht im Hauptfenster. Entsperrt wird in
/// jedem Fall im eigenen Fenster; das Master-Passwort durchläuft keinen Code,
/// den eine Website beeinflusst.
///
/// Das Entsperren zählt als Nachweis: Die Oberfläche meldet es als
/// Legitimation, und die folgende Rückfrage fällt in die Schonfrist.
/// Wann die Erweiterung zuletzt ums Entsperren gebeten hat (`triggerUnlock`).
fn entsperren_erbeten_um() -> &'static Mutex<Option<std::time::Instant>> {
    static UM: Mutex<Option<std::time::Instant>> = Mutex::new(None);
    &UM
}

fn entsperren_erbeten_merken() {
    if let Ok(mut um) = entsperren_erbeten_um().lock() {
        *um = Some(std::time::Instant::now());
    }
}

/// Ob eine selbständig eintreffende Anfrage aufs Entsperren warten darf.
///
/// Das ist der Fall, wenn bereits ums Entsperren gefragt wird oder die
/// Erweiterung eben darum gebeten hat. Das Fenster öffnet in einem eigenen
/// Thread, den die Folgeanfrage überholen kann; daher gilt eine kurze Frist
/// statt nur der Prüfung auf eine offene Rückfrage.
fn entsperren_erbeten() -> bool {
    let eben = entsperren_erbeten_um()
        .lock()
        .ok()
        .and_then(|um| *um)
        .is_some_and(|um| um.elapsed() < std::time::Duration::from_secs(10));
    eben || pending()
        .lock()
        .map(|m| m.values().any(|p| p.details.get("kind").and_then(Value::as_str) == Some("unlock")))
        .unwrap_or(false)
}

fn await_unlocked(app: &tauri::AppHandle) -> Result<(), Failure> {
    if is_open(app) {
        return Ok(());
    }

    // Wird bereits gefragt, öffnet sich keine zweite Anmeldemaske (ein
    // Formular mit mehreren Feldern löst oft mehrere Anfragen aus).
    let laeuft_schon = pending()
        .lock()
        .map(|m| m.values().any(|p| p.details.get("kind").and_then(Value::as_str) == Some("unlock")))
        .unwrap_or(false);

    let id = neue_id();
    let (tx, rx) = std::sync::mpsc::channel();

    if !laeuft_schon {
        let details = json!({ "id": id, "kind": "unlock" });

        pending()
            .lock()
            .map_err(|_| Failure(0, "Rückfrage blockiert.".into()))?
            .insert(id.clone(), Parked { tx, details: details.clone() });

        open_request_window(app, UNLOCK_HEIGHT);
        let _ = app.emit("browser-request", details);

        // Ist das Hauptfenster offen, wird dort ebenfalls entsperrt; das
        // beendet das Warten unten genauso.
        let _ = app.emit("browser-needs-unlock", json!({}));
    }

    let deadline = std::time::Instant::now() + UNLOCK_TIMEOUT;
    let mut ergebnis = Err(Failure(code::DATABASE_NOT_OPENED, "Die Datenbank blieb gesperrt.".into()));

    while std::time::Instant::now() < deadline {
        match rx.recv_timeout(std::time::Duration::from_millis(200)) {
            // Das kleine Fenster meldet sich nach dem Entsperren.
            Ok(entscheidung) => {
                ergebnis = match entscheidung.allow && is_open(app) {
                    true => Ok(()),
                    false => Err(Failure(code::DATABASE_NOT_OPENED, "Entsperren abgebrochen.".into())),
                };
                break;
            }
            // Ohne Meldung wird der Zustand selbst geprüft; so endet das Warten
            // auch nach dem Entsperren im Hauptfenster.
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if is_open(app) {
                    ergebnis = Ok(());
                    break;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    if !laeuft_schon {
        unpark(app, &id);
    }
    ergebnis
}

/// Nimmt eine Anfrage aus der Liste und schließt das Fenster, wenn keine
/// mehr wartet.
fn unpark(app: &tauri::AppHandle, id: &str) {
    if let Ok(mut map) = pending().lock() {
        map.remove(id);
    }

    // Steht noch eine andere Anfrage an, bleibt das Fenster stehen und zeigt
    // die nächste. Sonst wird es versteckt statt geschlossen, da das
    // Schließen verzögert abläuft und ein verstecktes Fenster sich
    // zuverlässig und schneller wieder zeigen lässt.
    let leer = pending().lock().map(|m| m.is_empty()).unwrap_or(true);
    if leer {
        if let Some(window) = app.get_webview_window(REQUEST_WINDOW) {
            let _ = window.hide();
        }
        spaeter_abbauen(app);
    }
}

/// Bereitschaftsdauer des versteckten Rückfragefensters, bevor es abgebaut
/// wird und seinen Speicher freigibt.
const BEREIT: std::time::Duration = std::time::Duration::from_secs(15);

/// Ob das Rückfragefenster gerade abgebaut wird und nicht mehr gezeigt werden
/// darf, siehe [`open_request_window`].
static ABBAU: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Serialisiert Abbau und Öffnen.
fn fenster_riegel() -> &'static Mutex<()> {
    static RIEGEL: Mutex<()> = Mutex::new(());
    &RIEGEL
}

/// Baut das versteckte Rückfragefenster nach [`BEREIT`] ab, wenn es dann noch
/// unbenutzt ist.
fn spaeter_abbauen(app: &tauri::AppHandle) {
    let app = app.clone();
    std::thread::spawn(move || {
        std::thread::sleep(BEREIT);
        let Ok(_riegel) = fenster_riegel().lock() else { return };
        let leer = pending().lock().map(|m| m.is_empty()).unwrap_or(false);
        let Some(window) = app.get_webview_window(REQUEST_WINDOW) else { return };
        if leer && !window.is_visible().unwrap_or(true) {
            ABBAU.store(true, std::sync::atomic::Ordering::SeqCst);
            if window.destroy().is_err() {
                ABBAU.store(false, std::sync::atomic::Ordering::SeqCst);
            }
        }
    });
}

/// Lehnt alle wartenden Anfragen ab (das Fenster wurde geschlossen).
fn deny_all_pending() {
    if let Ok(mut map) = pending().lock() {
        for (_, parked) in map.drain() {
            let _ = parked.tx.send(Decision { allow: false });
        }
    }
}

fn is_open(app: &tauri::AppHandle) -> bool {
    app.state::<Vault>().lock().is_ok_and(|v| v.db.is_some())
}

/// Wie [`is_open`], aber ohne auf einen beschäftigten Tresor zu warten, für
/// Antworten mit Frist. Ein beschäftigter Tresor gilt als offen.
fn offen_schnell(app: &tauri::AppHandle) -> bool {
    tresor_kurz(app).map_or(true, |v| v.db.is_some())
}

/// Öffnet das kleine Rückfragefenster über allen anderen Fenstern, mittig
/// über dem Browser. Es ist ein eigenes Fenster der Anwendung und kein
/// Browserinhalt, den eine Seite nachbauen könnte.
fn open_request_window(app: &tauri::AppHandle, hoehe: f64) {
    let _riegel = fenster_riegel().lock();

    // Wird das Fenster gerade abgebaut, wird das Ende abgewartet.
    let bis = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while ABBAU.load(std::sync::atomic::Ordering::SeqCst) && std::time::Instant::now() < bis {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    ABBAU.store(false, std::sync::atomic::Ordering::SeqCst);

    // Ist es bereits offen, wird es nur nach vorn geholt.
    if let Some(window) = app.get_webview_window(REQUEST_WINDOW) {
        // Die Höhe richtet sich nach dem Inhalt (Anmeldemaske oder Ja/Nein).
        let _ = window.set_size(tauri::LogicalSize::new(WINDOW_WIDTH, hoehe));
        let _ = window.unminimize();
        let _ = window.show();
        tastatur_hinein(&window);
        return;
    }

    let built = tauri::WebviewWindowBuilder::new(
        app,
        REQUEST_WINDOW,
        tauri::WebviewUrl::App("request.html".into()),
    )
    .title("WKeePass")
    .inner_size(WINDOW_WIDTH, hoehe)
    .resizable(false)
    .always_on_top(true)
    .focused(true)
    .center()
    .skip_taskbar(true)
    .build();

    // Das Fenster liegt oben und erhält den Tastaturfokus.
    if let Ok(window) = &built {
        tastatur_hinein(window);

        // Das Schließen über die Fensterleiste gilt als „Abbrechen“ und lehnt
        // die wartenden Anfragen ab.
        let fenster = window.clone();
        let handle = app.clone();
        window.on_window_event(move |event| match event {
            tauri::WindowEvent::CloseRequested { api, .. } => {
                api.prevent_close();
                deny_all_pending();
                let _ = fenster.hide();
                spaeter_abbauen(&handle);
            }
            tauri::WindowEvent::Destroyed => ABBAU.store(false, std::sync::atomic::Ordering::SeqCst),
            _ => {}
        });
    }

    // Rückfallweg ist das Hauptfenster, etwa wenn kein Fenstersystem
    // verfügbar ist.
    if built.is_err() {
        #[cfg(desktop)]
        crate::hauptfenster_zeigen(app);
    }
}

/// Holt das Fenster nach vorn **und** gibt der Seite darin die Tastatur.
///
/// Unter Linux setzt `set_focus` am Fenster den Tastaturfokus nicht in die
/// Webansicht; dieser wird daher zusätzlich dort gesetzt.
pub fn tastatur_hinein(window: &tauri::WebviewWindow) {
    let _ = window.set_focus();
    let _ = AsRef::<tauri::Webview>::as_ref(window).set_focus();
}

/// Name des Rückfragefensters.
const REQUEST_WINDOW: &str = "browser-request";

const WINDOW_WIDTH: f64 = 440.0;
/// Reicht für Ja/Nein oder ein einzelnes Feld.
const ASK_HEIGHT: f64 = 340.0;
/// Reicht zusätzlich für Dateiname, PIN und Master-Passwort.
const UNLOCK_HEIGHT: f64 = 440.0;

/// Holt das Hauptfenster nach vorn.
#[allow(dead_code)]
fn bring_to_front(app: &tauri::AppHandle) {
    #[cfg(desktop)]
    crate::hauptfenster_zeigen(app);
    #[cfg(not(desktop))]
    let _ = app;
}

fn now_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/* =========================================================
   Einträge suchen
   ========================================================= */

/// Ein Eintrag, der zur angefragten Adresse passt.
struct Candidate {
    /// Wie genau der Eintrag zur Adresse passt — größer ist besser.
    score: u32,
    uuid: String,
    title: String,
    username: String,
    password: String,
    group: String,
    totp: String,
    /// Frühere Entscheidung für genau diesen Rechnernamen, falls es eine gibt.
    decision: Option<bool>,
}

/// Der Schlüssel, unter dem eine Entscheidung am Eintrag hängt.
///
/// Dieselbe Form wie bei KeePassXC, damit dort dieselben Freigaben gelten.
const DECISION_PREFIX: &str = "KP_BROWSER_";

/// Wie `host_of`, aber für Stellen, die einen geliehenen Wert brauchen.
fn host_of_str(url: &str) -> Option<&str> {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let rest = rest.split(['/', '?', '#']).next()?;
    let host = rest.split(':').next()?;

    (!host.is_empty()).then_some(host)
}


fn matching_entries(
    app: &tauri::AppHandle,
    host: &str,
    path: &[String],
) -> Result<Vec<Candidate>, Failure> {
    let state = app.state::<Vault>();
    let vault = state.lock().map_err(|_| Failure(0, "Kern blockiert.".into()))?;
    let db = vault.database().map_err(|_| Failure(code::DATABASE_NOT_OPENED, "Datenbank ist zu.".into()))?;

    let bin = crate::state::recycle_bin(db);
    let mut out = Vec::new();

    for entry in db.iter_all_entries() {
        // Einträge im Papierkorb werden nicht angeboten.
        if bin.is_some_and(|b| entry.parent().id() == b) {
            continue;
        }

        // Passkeys haben kein Passwort und erscheinen nicht in der
        // Passwortauswahl; ihr Weg ist `passkeys-get`.
        if entry.get(crate::passkey::F_ID).is_some() {
            continue;
        }

        let urls = entry_urls(&entry);

        // Es zählt der beste Treffer unter allen Adressen des Eintrags.
        let Some(score) = urls.iter().filter_map(|u| match_score(u, host, path)).max() else {
            continue;
        };

        let decision = entry
            .custom_data
            .get(&format!("{DECISION_PREFIX}{host}"))
            .and_then(|item| item.value.as_ref())
            .map(|value| als_text(value) == "true");

        // Ein ausdrückliches Nein gilt; es wird nicht erneut gefragt.
        if decision == Some(false) {
            continue;
        }

        out.push(Candidate {
            score,
            uuid: entry.id().uuid().to_string(),
            title: entry.get_title().unwrap_or_default().to_string(),
            username: entry.get_username().unwrap_or_default().to_string(),
            password: entry.get_password().unwrap_or_default().to_string(),
            group: crate::state::folder_path(db, entry.parent().id()),
            totp: entry
                .get_raw_otp_value()
                .and_then(|raw| current_totp(raw))
                .unwrap_or_default(),
            decision,
        });
    }

    // Genauester Treffer zuerst; die Erweiterung zeigt die Liste in dieser
    // Reihenfolge.
    out.sort_by(|a, b| b.score.cmp(&a.score));

    Ok(out)
}

/* =========================================================
   Die übrigen Aktionen
   ========================================================= */

/// Legt einen Eintrag an oder ändert einen vorhandenen.
fn set_login(app: &tauri::AppHandle, inner: &Value) -> Result<Value, Failure> {
    let url = inner.get("url").and_then(Value::as_str).unwrap_or_default().to_string();
    let login = inner.get("login").and_then(Value::as_str).unwrap_or_default().to_string();
    let password = inner
        .get("password")
        .and_then(Value::as_str)
        .ok_or_else(|| Failure(code::EMPTY_MESSAGE_RECEIVED, "Kein Passwort angegeben.".into()))?
        .to_string();

    let uuid = inner.get("uuid").and_then(Value::as_str).map(str::to_string);
    let host = host_of(&url).unwrap_or_else(|| url.clone());

    let answer = ask_user(
        app,
        json!({
            "kind": if uuid.is_some() { "update" } else { "create" },
            "host": host,
            "url": url,
            "login": login,
        }),
    )?;
    if !answer.allow {
        return Err(Failure(code::ACTION_CANCELLED_OR_DENIED, "Speichern abgelehnt.".into()));
    }

    let group = inner
        .get("group")
        .and_then(Value::as_str)
        .filter(|g| !g.is_empty())
        .unwrap_or(crate::state::ROOT_LABEL)
        .to_string();

    let state = app.state::<Vault>();
    let mut vault = state.lock().map_err(|_| Failure(0, "Kern blockiert.".into()))?;
    let db = vault.database_mut().map_err(|_| Failure(code::DATABASE_NOT_OPENED, "Datenbank ist zu.".into()))?;

    let existing = uuid.as_deref().and_then(|u| crate::database::entry_id_of(db, u));

    let id = match existing {
        Some(id) => id,
        None => {
            let target = crate::state::ensure_group(db, &group);
            let mut parent = db.group_mut(target).ok_or_else(|| Failure(code::NO_GROUPS_FOUND, "Ordner weg.".into()))?;
            parent.add_entry().id()
        }
    };

    let mut node = db.entry_mut(id).ok_or_else(|| Failure(0, "Eintrag weg.".into()))?;

    if existing.is_none() {
        node.set_unprotected(keepass::db::fields::TITLE, host.clone());
        node.set_unprotected(keepass::db::fields::URL, url);
    }
    node.set_unprotected(keepass::db::fields::USERNAME, login);
    node.set_protected(keepass::db::fields::PASSWORD, password);

    let hash = database_hash_locked(db);
    persist(app);
    crate::favicon::im_hintergrund(app, vec![id.uuid().to_string()], false);
    // Antwort im Format von KeePassXC; die Erweiterung meldet „gespeichert“
    // nur bei `error: ""`.
    Ok(json!({ "count": null, "entries": null, "error": "", "hash": hash }))
}

/// Der gerade gültige TOTP-Code eines Eintrags.
///
/// Nur nach Rückfrage, wie beim Abruf der Zugangsdaten, da der Code der
/// zweite Faktor ist. Wurde bereits für `get-logins` gefragt, fällt diese
/// Frage in die Schonfrist.
fn get_totp(app: &tauri::AppHandle, inner: &Value, client: String) -> Result<Value, Failure> {
    let uuid = inner
        .get("uuid")
        .and_then(Value::as_str)
        .ok_or_else(|| Failure(code::NO_VALID_UUID_PROVIDED, "Kein Eintrag angegeben.".into()))?;

    // Zuerst wird geprüft, ob Eintrag und Code existieren. Der Tresor wird
    // nicht über die Rückfrage hinweg gehalten.
    let (titel, hat_code) = {
        let state = app.state::<Vault>();
        let vault = state.lock().map_err(|_| Failure(0, "Kern blockiert.".into()))?;
        let db = vault.database().map_err(|_| Failure(code::DATABASE_NOT_OPENED, "Datenbank ist zu.".into()))?;
        let id = crate::database::entry_id_of(db, uuid)
            .ok_or_else(|| Failure(code::NO_VALID_UUID_PROVIDED, "Eintrag nicht gefunden.".into()))?;
        match db.entry(id) {
            Some(e) => (e.get_title().map(str::to_string).unwrap_or_default(), e.get_raw_otp_value().is_some()),
            None => (String::new(), false),
        }
    };
    if !hat_code {
        return Err(Failure(code::NO_VALID_UUID_PROVIDED, "Für diesen Eintrag gibt es keinen Code.".into()));
    }

    let answer = ask_user(
        app,
        json!({
            "kind": "totp",
            "client": client,
            "host": titel,
            "entries": [{ "uuid": uuid, "name": titel }],
        }),
    )?;
    if !answer.allow {
        return Err(Failure(code::ACTION_CANCELLED_OR_DENIED, "Zugriff abgelehnt.".into()));
    }

    let state = app.state::<Vault>();
    let vault = state.lock().map_err(|_| Failure(0, "Kern blockiert.".into()))?;
    let db = vault.database().map_err(|_| Failure(code::DATABASE_NOT_OPENED, "Datenbank ist zu.".into()))?;
    let id = crate::database::entry_id_of(db, uuid)
        .ok_or_else(|| Failure(code::NO_VALID_UUID_PROVIDED, "Eintrag nicht gefunden.".into()))?;

    let code = db
        .entry(id)
        .and_then(|e| e.get_raw_otp_value().map(str::to_string))
        .and_then(|raw| current_totp(&raw))
        .ok_or_else(|| Failure(code::NO_VALID_UUID_PROVIDED, "Für diesen Eintrag gibt es keinen Code.".into()))?;

    Ok(json!({ "totp": code }))
}

/// Sperrt die Datenbank auf Wunsch der Erweiterung.
fn lock_database(app: &tauri::AppHandle) -> Result<Value, Failure> {
    sperren(app, "Über die Browser-Erweiterung gesperrt.").map_err(|e| Failure(0, e))?;
    Ok(json!({}))
}

/// Sperrt die Datenbank von außerhalb der Oberfläche — Erweiterung oder
/// Leistensymbol — und sagt es allen weiter.
pub fn sperren(app: &tauri::AppHandle, grund: &str) -> Result<(), String> {
    app.state::<Vault>().lock().map_err(|_| "Kern blockiert.".to_string())?.clear();
    announce(true);
    let _ = app.emit("vault-locked", grund);
    Ok(())
}

/// Alle Ordner als Baum — die Erweiterung bietet sie beim Speichern an.
fn database_groups(app: &tauri::AppHandle) -> Result<Value, Failure> {
    let state = app.state::<Vault>();
    let vault = state.lock().map_err(|_| Failure(0, "Kern blockiert.".into()))?;
    let db = vault.database().map_err(|_| Failure(code::DATABASE_NOT_OPENED, "Datenbank ist zu.".into()))?;

    fn walk(db: &keepass::Database, id: keepass::db::GroupId) -> Value {
        let Some(group) = db.group(id) else { return Value::Null };

        json!({
            "name": group.name.clone(),
            "uuid": id.uuid().to_string(),
            "children": group
                .groups()
                .map(|child| walk(db, child.id()))
                .filter(|v| !v.is_null())
                .collect::<Vec<_>>(),
        })
    }

    Ok(json!({ "groups": { "groups": [walk(db, db.root().id())] } }))
}

/// Legt einen Ordner an. Der Name kommt als Pfad mit Schrägstrichen.
fn create_group(app: &tauri::AppHandle, inner: &Value) -> Result<Value, Failure> {
    let path = inner
        .get("groupName")
        .and_then(Value::as_str)
        .filter(|p| !p.trim().is_empty())
        .ok_or_else(|| Failure(code::CANNOT_CREATE_NEW_GROUP, "Kein Name angegeben.".into()))?;

    let state = app.state::<Vault>();
    let mut vault = state.lock().map_err(|_| Failure(0, "Kern blockiert.".into()))?;
    let db = vault.database_mut().map_err(|_| Failure(code::DATABASE_NOT_OPENED, "Datenbank ist zu.".into()))?;

    let id = crate::state::ensure_group(db, path);

    let antwort = json!({ "name": path, "uuid": id.uuid().to_string() });
    persist(app);
    Ok(antwort)
}

/// Entfernt einen Eintrag — nach Rückfrage, und nur in den Papierkorb.
fn delete_entry(app: &tauri::AppHandle, inner: &Value) -> Result<Value, Failure> {
    let uuid = inner
        .get("uuid")
        .and_then(Value::as_str)
        .ok_or_else(|| Failure(code::NO_VALID_UUID_PROVIDED, "Kein Eintrag angegeben.".into()))?
        .to_string();

    let answer = ask_user(app, json!({ "kind": "delete", "uuid": uuid }))?;
    if !answer.allow {
        return Err(Failure(code::ACTION_CANCELLED_OR_DENIED, "Löschen abgelehnt.".into()));
    }

    // Über das vorhandene Kommando, damit dieselben Regeln gelten wie im
    // Fenster: zuerst in den Papierkorb, endgültig erst beim zweiten Mal.
    crate::entries::vault_delete_entry(app.state::<Vault>(), uuid)
        .map_err(|e| Failure(code::PASSKEYS_UNKNOWN_ERROR, e))?;

    persist(app);
    Ok(json!({}))
}

/* =========================================================
   Passwörter erzeugen
   ========================================================= */

/// Ein zufälliges Passwort für die Erweiterung.
///
/// Leicht verwechselbare Zeichen (null und O, eins und l) werden
/// ausgelassen.
fn generate_password() -> String {
    use rand_core::RngCore;

    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789\
                              !#$%&*+-=?@^_";
    const LENGTH: usize = 24;

    let mut raw = [0u8; LENGTH];
    rand_core::OsRng.fill_bytes(&mut raw);

    // Der Divisionsrest verzerrt die Verteilung geringfügig, da 256 kein
    // Vielfaches der Alphabetlänge ist.
    raw.iter().map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char).collect()
}

/* =========================================================
   Was die Oberfläche steuert
   ========================================================= */

/// Der Zustand der Anbindung, für den Abschnitt in den Einstellungen.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    /// Der Kanal ist eingehängt und nimmt Verbindungen an.
    pub listening: bool,
    /// Wo er liegt — damit man bei Problemen nachsehen kann.
    pub socket: String,
    /// Browser, für die ein Manifest von uns eingetragen ist.
    pub installed: Vec<String>,
    /// Browser, bei denen ein Manifest eingetragen werden könnte.
    pub available: Vec<String>,
    /// Verknüpfte Browser aus der offenen Datenbank.
    pub associations: Vec<String>,
}

#[tauri::command]
pub fn browser_status(state: tauri::State<'_, Vault>) -> Result<Status, String> {
    let socket = route::socket_path();
    let program = route::program_path().ok();

    let mut installed = Vec::new();
    let mut available = Vec::new();

    for target in route::targets().into_iter().filter(route::Target::installed) {
        // „Eingetragen“ bedeutet: Das Manifest zeigt auf dieses Programm;
        // andernfalls gehört es KeePassXC.
        let ours = program.as_ref().is_some_and(|p| target.is_ours(p));

        if ours { installed.push(target.name.to_string()) } else { available.push(target.name.to_string()) }
    }

    let associations = {
        let vault = state.lock().map_err(|_| "Kern blockiert.".to_string())?;
        match vault.database() {
            Ok(db) => db
                .meta
                .custom_data
                .keys()
                .filter_map(|key| key.strip_prefix(ASSOCIATION_PREFIX).map(str::to_string))
                .collect(),
            Err(_) => Vec::new(),
        }
    };

    Ok(Status {
        listening: LISTENING.load(std::sync::atomic::Ordering::Relaxed),
        socket: socket.to_string_lossy().to_string(),
        installed,
        available,
        associations,
    })
}

/// Trägt uns bei allen eingerichteten Browsern ein.
#[tauri::command]
pub fn browser_install() -> Result<Vec<route::Outcome>, String> {
    let program = route::program_path()?;
    Ok(route::install(&program))
}

/// Nimmt den Eintrag zurück — und stellt, wo möglich, KeePassXC wieder her.
#[tauri::command]
pub fn browser_uninstall() -> Result<Vec<route::Outcome>, String> {
    let program = route::program_path()?;
    Ok(route::uninstall(&program))
}

/// Löst die Verknüpfung eines Browsers.
///
/// Der Browser fragt danach erneut um Erlaubnis. Die Freigaben je Eintrag
/// bleiben bestehen, da sie am Eintrag hängen.
#[tauri::command]
pub fn browser_forget(state: tauri::State<'_, Vault>, name: String) -> Result<bool, String> {
    let mut vault = state.lock().map_err(|_| "Kern blockiert.".to_string())?;
    let db = vault.database_mut()?;

    Ok(db.meta.custom_data.remove(&format!("{ASSOCIATION_PREFIX}{name}")).is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Eine Antwort beantwortet beide Anfragen eines Formulars; eine Anfrage
    /// einer anderen Seite bleibt offen.
    #[test]
    fn eine_antwort_fuer_dieselbe_frage() {
        let parken = |kind: &str, host: &str| {
            let id = neue_id();
            let (tx, rx) = std::sync::mpsc::channel();
            let details = json!({ "id": id, "kind": kind, "host": host, "guard": "identify" });
            pending().lock().unwrap().insert(id.clone(), Parked { tx, details });
            (id, rx)
        };
        let (erste, rx1) = parken("logins", "example.org");
        let (_, rx2) = parken("logins", "example.org");
        let (andere, rx3) = parken("logins", "andere.org");
        assert_ne!(erste, neue_id(), "Kennungen sind eindeutig");

        assert!(browser_answer(erste, true).unwrap());
        assert!(rx1.try_recv().unwrap().allow);
        assert!(rx2.try_recv().unwrap().allow, "dieselbe Frage ist mitbeantwortet");
        assert!(rx3.try_recv().is_err(), "andere Seite wartet weiter");

        assert!(browser_answer(andere, false).unwrap());
        assert!(!rx3.try_recv().unwrap().allow);
        assert!(pending().lock().unwrap().is_empty());
    }
    use crate::keepass_extension::protocol::{self, KeyPair};

    /// Entsperren zählt als Ausweisen, Sperren beendet die Frist sofort.
    #[test]
    fn entsperren_beginnt_die_schonfrist() {
        let stand = || *last_identified().lock().unwrap();

        announce(true);
        assert!(stand().is_none(), "gesperrt: keine Frist");

        announce(false);
        let seit = stand().expect("entsperrt: die Frist läuft");
        assert!(seit.elapsed() < std::time::Duration::from_secs(5));

        announce(true);
        assert!(stand().is_none(), "wieder gesperrt: Frist vorbei");
    }

    /// Entspricht der Prüfung aus `nacl-util.min.js` der Erweiterung.
    fn ist_gueltiges_base64(s: &str) -> bool {
        let gueltig = |c: char| c.is_ascii_alphanumeric() || c == '+' || c == '/';

        if s.len() % 4 != 0 {
            return false;
        }
        let (rumpf, schwanz) = s.split_at(s.len().saturating_sub(4));
        rumpf.chars().all(gueltig)
            && match schwanz {
                "" => true,
                t if t.ends_with("==") => t[..2].chars().all(gueltig),
                t if t.ends_with('=') => t[..3].chars().all(gueltig),
                t => t.chars().all(gueltig),
            }
    }

    /// Baut eine Verbindung mit abgeschlossenem Schlüsseltausch.
    fn verbindung() -> (Connection, KeyPair, Value) {
        let client = KeyPair::generate();
        let mut conn = Connection::new();

        let nonce = [7u8; protocol::NONCE_LEN];
        let antwort = conn.change_public_keys(&json!({
            "action": "change-public-keys",
            "publicKey": client.public_base64(),
            "nonce": protocol::encode(&nonce),
        }));

        (conn, client, antwort)
    }

    #[test]
    fn schluesseltausch_liefert_sauberes_base64() {
        let (_, _, antwort) = verbindung();

        let key = antwort["publicKey"].as_str().unwrap();
        let nonce = antwort["nonce"].as_str().unwrap();

        assert!(ist_gueltiges_base64(key), "publicKey: {key}");
        assert!(ist_gueltiges_base64(nonce), "nonce: {nonce}");
        assert_eq!(protocol::decode(key).unwrap().len(), 32);
        assert_eq!(protocol::decode(nonce).unwrap().len(), 24);
    }

    #[test]
    fn verpackte_antwort_ist_fuer_die_erweiterung_lesbar() {
        let (conn, client, _) = verbindung();

        // Die Erweiterung schickt eine Anfrage mit eigenem Nonce …
        let anfrage_nonce = [42u8; protocol::NONCE_LEN];
        let verpackt = conn.wrap(
            "get-databasehash",
            &json!({ "hash": "abc123", "success": "true", "version": PROTOCOL_VERSION }),
            &anfrage_nonce,
        );

        let message = verpackt["message"].as_str().expect("kein message-Feld");
        let nonce = verpackt["nonce"].as_str().expect("kein nonce-Feld");

        // … beide Felder bestehen die Base64-Prüfung.
        assert!(ist_gueltiges_base64(message), "message: {message}");
        assert!(ist_gueltiges_base64(nonce), "nonce: {nonce}");

        // Das Nonce ist das erhöhte.
        assert_eq!(nonce, protocol::encode(&protocol::increment_nonce(&anfrage_nonce)));

        // Die Gegenstelle kann die Antwort entschlüsseln.
        let gegenstelle = protocol::Session::new(&client, &conn.keys.public_base64()).unwrap();
        let klartext = gegenstelle
            .open(message, &protocol::decode_nonce(nonce).unwrap())
            .expect("Erweiterung könnte die Antwort nicht entschlüsseln");

        let gelesen: Value = serde_json::from_slice(&klartext).unwrap();
        assert_eq!(gelesen["hash"], "abc123");
        assert_eq!(gelesen["success"], "true");
    }

    /// Wie `match_score` die Adresse einer Anfrage zerlegt.
    fn treffer(eintrag: &str, angefragt: &str) -> Option<u32> {
        let (host, path) = split_url(angefragt).unwrap();
        match_score(eintrag, &host, &path)
    }

    /// Genau eine Hülle um den Ausweis; die zweite legt die Erweiterung selbst
    /// an (`sendPasskeysResponse` in passkeys-utils.js).
    #[test]
    fn passkey_antwort_hat_die_huelle_der_erweiterung() {
        let antwort = json!({ "response": credential("abc", json!({
            "clientDataJSON": "eyJ9",
            "authenticatorData": "AAA",
            "signature": "MEQ",
            "userHandle": Value::Null,
        })) });

        // Das erhält `createPublicKeyCredential`.
        let key = &antwort["response"];
        assert!(key.get("publicKey").is_none(), "eine Hülle zu viel");
        assert_eq!(key["id"], "abc");
        assert_eq!(key["type"], "public-key");
        assert_eq!(key["authenticatorAttachment"], "platform");

        // createAssertionResponse liest genau diese vier Felder.
        for feld in ["clientDataJSON", "authenticatorData", "signature", "userHandle"] {
            assert!(key["response"].get(feld).is_some(), "{feld} fehlt");
        }
    }

    #[test]
    fn genauer_treffer_schlaegt_groeberen() {
        let url = "https://shop.example.com/kunden/login";

        let genau = treffer("https://shop.example.com/kunden/login", url).unwrap();
        let pfad = treffer("https://shop.example.com/kunden", url).unwrap();
        let rechner = treffer("https://shop.example.com", url).unwrap();
        let domain = treffer("https://example.com", url).unwrap();

        assert!(genau > pfad, "{genau} > {pfad}");
        assert!(pfad > rechner, "{pfad} > {rechner}");
        assert!(rechner > domain, "{rechner} > {domain}");
    }

    #[test]
    fn fremder_rechner_passt_nicht() {
        let url = "https://example.com/login";

        assert!(treffer("https://notexample.com", url).is_none());
        // Ein Eintrag für die Unterdomain gilt nicht für die Hauptdomain.
        assert!(treffer("https://shop.example.com", url).is_none());
    }

    #[test]
    fn abweichender_pfad_bleibt_erreichbar_aber_hinten() {
        let url = "https://example.com/konto/login";

        let passend = treffer("https://example.com/konto", url).unwrap();
        let daneben = treffer("https://example.com/impressum", url).unwrap();

        assert!(daneben < passend, "{daneben} < {passend}");
    }

    #[test]
    fn eintrag_ohne_pfad_gilt_fuer_die_ganze_seite() {
        let tief = treffer("example.com", "https://example.com/a/b/c").unwrap();
        let flach = treffer("example.com", "https://example.com/").unwrap();
        assert_eq!(tief, flach);
    }

    #[test]
    fn port_anmeldedaten_und_anhaengsel_stoeren_nicht() {
        let (host, path) = split_url("https://nutzer:geheim@example.com:8443/a/b?x=1#top").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(path, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn eine_ebene_hoeher_zaehlt_mehr_als_zwei() {
        let url = "https://a.b.example.com/";
        let nah = treffer("https://b.example.com", url).unwrap();
        let fern = treffer("https://example.com", url).unwrap();
        assert!(nah > fern, "{nah} > {fern}");
    }

    /// `verifyDatabaseResponse` prüft das Nonce im Inhalt, nicht nur auf dem
    /// Umschlag; fehlt es dort, scheitert die Erweiterung mit „invalid
    /// encoding“.
    #[test]
    fn das_nonce_steht_auch_im_verschluesselten_inhalt() {
        let (conn, client, _) = verbindung();

        let anfrage_nonce = [42u8; protocol::NONCE_LEN];
        let erwartet = protocol::encode(&protocol::increment_nonce(&anfrage_nonce));

        let verpackt = conn.wrap("get-databasehash", &json!({ "hash": "abc123" }), &anfrage_nonce);

        let gegenstelle = protocol::Session::new(&client, &conn.keys.public_base64()).unwrap();
        let klartext = gegenstelle
            .open(verpackt["message"].as_str().unwrap(), &protocol::decode_nonce(&erwartet).unwrap())
            .unwrap();

        let inhalt: Value = serde_json::from_slice(&klartext).unwrap();

        // checkNonceLength(response.nonce): 24 Bytes erforderlich
        let innen = inhalt["nonce"].as_str().expect("kein nonce im Inhalt");
        assert_eq!(protocol::decode(innen).unwrap().len(), protocol::NONCE_LEN);

        // response.nonce !== nonce: innen und außen müssen gleich sein
        assert_eq!(innen, erwartet);
        assert_eq!(verpackt["nonce"].as_str().unwrap(), erwartet);
    }

    #[test]
    fn datenbank_kennung_bleibt_beim_umbenennen() {
        let mut db = keepass::Database::new();
        let vorher = database_hash_locked(&db);
        db.meta.database_name = Some("Neuer Name".into());
        assert_eq!(database_hash_locked(&db), vorher);
    }

    #[test]
    fn bekannter_schluessel_wird_wiedererkannt() {
        let mut db = keepass::Database::new();
        db.meta.custom_data.insert(
            format!("{ASSOCIATION_PREFIX}WKeePass JaLT6Q"),
            keepass::db::CustomDataItem {
                value: Some(keepass::db::CustomDataValue::String("schluessel".into())),
                last_modification_time: None,
            },
        );
        assert_eq!(association_with_key(&db, "schluessel").as_deref(), Some("WKeePass JaLT6Q"));
        assert_eq!(association_with_key(&db, "anderer"), None);
    }

    /// Eine Verknüpfung übersteht Speichern und Wiedereinlesen.
    #[test]
    fn verknuepfung_uebersteht_speichern() {
        const KEY: &str = "lRnhOlGs4yUfqJAhd1Rv1ClXbrEOEhq3HKJFfNG0rFk=";
        let mut db = keepass::Database::new();
        db.meta.custom_data.insert(
            format!("{ASSOCIATION_PREFIX}WKeePass abc"),
            keepass::db::CustomDataItem {
                // Base64 wie von der Erweiterung; wird nach dem Einlesen zu
                // `Binary`.
                value: Some(keepass::db::CustomDataValue::String(KEY.into())),
                last_modification_time: Some(keepass::db::Times::now()),
            },
        );
        let mut bytes = Vec::new();
        db.save(&mut bytes, keepass::DatabaseKey::new().with_password("test")).unwrap();
        let wieder = keepass::Database::parse(&bytes, keepass::DatabaseKey::new().with_password("test")).unwrap();
        assert_eq!(association_with_key(&wieder, KEY).as_deref(), Some("WKeePass abc"));
        assert_eq!(stand_merken(&wieder).schluessel.get("WKeePass abc").map(String::as_str), Some(KEY));
        stand_vergessen();
    }

    /// Passkeys verlangen mindestens einen Nachweis, auch bei den Stufen
    /// „Nichts“ oder „Bestätigen“.
    #[test]
    fn untergrenze_der_rueckfrage() {
        assert_eq!(Guard::Never.max(Guard::Identify), Guard::Identify);
        assert_eq!(Guard::Confirm.max(Guard::Identify), Guard::Identify);
        assert_eq!(Guard::Identify.max(Guard::Never), Guard::Identify);
        assert_eq!(Guard::Confirm.max(Guard::Never), Guard::Confirm);
    }

    /// Ein Knopfdruck ist kein Nachweis: Er hält die Schonfrist für
    /// „Bestätigen“ offen, nicht für einen Passkey.
    #[test]
    fn knopfdruck_ist_kein_nachweis() {
        let frist = std::time::Duration::from_secs(60);
        *last_identified().lock().unwrap() = None;
        *last_confirmed().lock().unwrap() = Some(std::time::Instant::now());
        assert!(frisch(last_confirmed(), frist));
        assert!(!frisch(last_identified(), frist));
        *last_confirmed().lock().unwrap() = None;
    }

    /// „Immer erlauben“ steht als „true“ am Eintrag — auch das liest die
    /// Bibliothek als Base64.
    #[test]
    fn zusatzangabe_true_bleibt_text() {
        use base64::Engine as _;
        let gelesen = keepass::db::CustomDataValue::Binary(base64::engine::general_purpose::STANDARD.decode("true").unwrap());
        assert_eq!(als_text(&gelesen), "true");
    }

    /// Ist der Tresor beim Speichern beschäftigt, antworten `get-databasehash`
    /// und `test-associate` aus dem gemerkten Stand; dieser enthält dieselbe
    /// Kennung und dieselben Schlüssel und verfällt beim Sperren.
    #[test]
    fn gemerkter_stand_kennt_verknuepfungen() {
        let mut db = keepass::Database::new();
        db.meta.custom_data.insert(
            format!("{ASSOCIATION_PREFIX}Firefox"),
            keepass::db::CustomDataItem {
                value: Some(keepass::db::CustomDataValue::String("schluessel".into())),
                last_modification_time: None,
            },
        );
        db.meta.custom_data.insert(
            "fremd".into(),
            keepass::db::CustomDataItem {
                value: Some(keepass::db::CustomDataValue::String("nicht verknüpft".into())),
                last_modification_time: None,
            },
        );

        let stand = stand_merken(&db);
        assert_eq!(stand.hash, database_hash_locked(&db));
        assert_eq!(stand.schluessel.get("Firefox").map(String::as_str), Some("schluessel"));
        assert_eq!(stand.schluessel.len(), 1, "nur Verknüpfungen, keine anderen Daten");
        assert!(stand_zuletzt().is_some());

        // Gesperrt bleibt der Stand: Sonst gibt die Erweiterung vor einem
        // Passkey auf, bevor wir ums Entsperren bitten können.
        assert!(stand_zuletzt().is_some_and(|s| s.hash == stand.hash));
        stand_vergessen();
    }

}

/* =========================================================
   Wie streng wird gefragt?
   ========================================================= */

/// Was vor der Herausgabe von Zugangsdaten verlangt wird — der Reihe nach
/// strenger, damit sich eine Untergrenze mit `max` setzen lässt.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug)]
pub enum Guard {
    /// Gar nichts. Der verknüpfte Browser bekommt, was er anfragt.
    ///
    /// Der Browser hat sich mit seinem Schlüssel ausgewiesen und die
    /// Datenbank ist offen. Keine Voreinstellung, da der Schlüssel auf
    /// demselben Rechner liegt, an dem auch andere Personen sitzen können.
    Never,
    /// Nur ein Knopfdruck: Abbrechen oder Übernehmen. Kein Nachweis.
    Confirm,
    /// PIN, Master-Passwort oder Fingerabdruck. Die Voreinstellung.
    Identify,
}

/// Liest die Einstellung `browser.guard`.
///
/// Fehlt sie oder ist sie unlesbar, gilt die strengere Stufe `Identify`.
fn guard(app: &tauri::AppHandle) -> Guard {
    match crate::settings::value(app, "browser.guard").as_ref().and_then(Value::as_str) {
        Some("never") => Guard::Never,
        Some("confirm") => Guard::Confirm,
        _ => Guard::Identify,
    }
}
