//! Die Gegenstelle: was über den Kanal gesprochen wird.
//!
//! Hier steht das, was sonst KeePassXC beantwortet. Der Weg dorthin —
//! Manifest, Kanalpfad, Sprachrohr — steht nebenan in `route`.
//!
//! # Der Ablauf einer Sitzung
//!
//! ```text
//! Erweiterung                          wir
//!     │  change-public-keys  (unverschlüsselt)
//!     │ ─────────────────────────────────▶
//!     │ ◀─────────────────────────────────  unser öffentlicher Schlüssel
//!     │
//!     │  ab jetzt ist alles verschlüsselt
//!     │
//!     │  associate / test-associate       Wiedererkennung
//!     │  get-databasehash                 welche Datenbank ist offen?
//!     │  get-logins                       Zugangsdaten — mit Rückfrage
//! ```
//!
//! # Zwei Schlüsselpaare, die nicht zu verwechseln sind
//!
//! **Sitzungsschlüssel** entstehen bei jeder Verbindung neu und
//! verschlüsseln den Verkehr. Sie sind nach dem Schließen wertlos.
//!
//! **Verknüpfungsschlüssel** entstehen einmal beim erstmaligen Verbinden und
//! landen dauerhaft in der Datenbank. Sie verschlüsseln nichts — sie belegen
//! nur, dass dieser Browser schon einmal zugelassen wurde. Wer sie
//! verwechselt, baut eine Anbindung, die nach jedem Neustart nach
//! Bestätigung fragt oder, schlimmer, gar keine mehr verlangt.
//!
//! # Was hier bewusst *nicht* passiert
//!
//! Entsperrt wird nie über diesen Kanal. Das Master-Passwort wanderte sonst
//! durch Code, den eine Website beeinflussen kann. Ist die Datenbank zu,
//! wartet die Anfrage und das eigene Fenster fragt.

use std::io::{Read, Write};
use std::sync::Mutex;

use serde_json::{json, Value};
use tauri::{Emitter, Manager};

use super::protocol::{self, KeyPair, Nonce, Session};
use super::route;
use crate::Vault;

/// Der Schlüssel, unter dem eine Verknüpfung in der Datenbank steht.
///
/// Dieselbe Form wie bei KeePassXC, damit dieselbe Datei in beiden
/// Programmen dieselben Browser wiedererkennt.
const ASSOCIATION_PREFIX: &str = "KPXC_BROWSER_";

/// Der Protokollstand, den wir sprechen — **nicht** unsere eigene Fassung.
///
/// Die Erweiterung liest dieses Feld als Angabe darüber, welchen Umfang die
/// Gegenstelle beherrscht, und wertet es an zwei Stellen aus:
///
///   * `keepass.requiredKeePassXC = '2.6.0'` — alles darunter wird
///     abgewiesen. Mit unserer eigenen `0.1.0` hieß es „alte Version",
///     obwohl gar nichts fehlte.
///   * `keePassXCUpdateAvailable()` vergleicht zusätzlich mit der neuesten
///     KeePassXC-Ausgabe, die sie sich von GitHub holt. Liegt unsere Zahl
///     darunter, erscheint der Hinweis zum Herunterladen.
///
/// Deshalb steht hier die zum Zeitpunkt des Schreibens neueste Ausgabe.
/// Erscheint dort eine neuere, kehrt der Hinweis zurück — abschalten lässt
/// er sich in den Einstellungen der Erweiterung unter „Nach Updates suchen".
/// Eine absurd hohe Zahl wäre die Alternative, aber sie stünde dem Nutzer
/// dann sichtbar als Unsinn in der Erweiterung.
const PROTOCOL_VERSION: &str = "2.7.12";

/// Die Fehlercodes der Erweiterung.
///
/// Sie sind keine Nummerierung nach Gutdünken: `handleResponse` verzweigt
/// danach, und `kpErrors.getError(code)` schlägt daraus den Text nach, den
/// der Nutzer zu sehen bekommt. Ein Code außerhalb der Tabelle lässt die
/// Erweiterung über `errorMessages[code].msg` stolpern — dann steht dort
/// „Fehler festgestellt:" und nichts dahinter.
///
/// Übernommen aus `background/client.js` der Erweiterung.
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
/// Läuft in einem eigenen Faden; jede Verbindung bekommt nochmal einen.
/// Das ist vertretbar, weil es um eine Handvoll Browser geht und nicht um
/// Tausende Verbindungen — und weil eine Anfrage auf die Rückfrage beim
/// Nutzer wartet, also lange stillsteht.
pub fn start(app: tauri::AppHandle) {
    #[cfg(not(windows))]
    std::thread::spawn(move || {
        if let Err(err) = listen(app) {
            eprintln!("Browser-Anbindung nicht gestartet: {err}");
        }
    });

    #[cfg(windows)]
    {
        // Benannte Pipes brauchen eine eigene Anbindung; noch nicht gebaut.
        let _ = app;
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

    // Ein Socket überlebt einen Absturz als Datei, und ohne Aufräumen
    // scheiterte jeder weitere Start mit „Adresse bereits vergeben".
    //
    // Aber nicht blind wegräumen: Läuft noch eine andere Ausgabe der
    // Anwendung, nähmen wir ihr den Kanal ab. Die Erweiterung landete dann
    // bei uns — und wir haben keine Datenbank offen, während die andere sie
    // hat. Der Nutzer sähe „Datenbank ist zu" vor einem offenen Fenster.
    //
    // Der Unterschied zwischen „verwaist" und „belegt" ist genau eine
    // Verbindungsaufnahme: Antwortet jemand, lassen wir die Finger davon.
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

    // Nur der Benutzer selbst. Ohne das dürfte jeder andere Benutzer des
    // Rechners Zugangsdaten anfragen.
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

    // Der Zustand der Verbindung wird geteilt, die Schreibseite auch.
    let connection = Arc::new(Mutex::new(Connection::new()));
    let writer = Arc::new(Mutex::new(match stream.try_clone() {
        Ok(clone) => clone,
        Err(_) => return,
    }));

    let mut reader = stream;
    let mut buffer = [0u8; 64 * 1024];
    let mut incoming = super::JsonStream::new();

    loop {
        let Ok(read) = reader.read(&mut buffer) else { break };
        if read == 0 {
            break;
        }

        // Auf dem Kanal liegt nacktes JSON ohne Längenangabe — genau wie bei
        // KeePassXC. Eine Portion kann deshalb zwei Nachrichten enthalten
        // oder eine halbe; `JsonStream` sortiert das.
        for message in incoming.push(&buffer[..read]) {
            trace("→", &message);

            // Der Schlüsseltausch bleibt hier, im Lesefaden.
            //
            // Er dauert Mikrosekunden, und alles Weitere hängt an ihm: Wer
            // ihn nebenläufig behandelte, riskierte, dass die nächste
            // Nachricht schon entschlüsselt werden soll, bevor der Schlüssel
            // steht.
            let action = message.get("action").and_then(Value::as_str).unwrap_or_default();
            if action == "change-public-keys" {
                let answer = connection.lock().map(|mut c| c.change_public_keys(&message));
                let Ok(answer) = answer else { return };
                if send(&writer, &answer).is_err() {
                    return;
                }
                continue;
            }

            // Alles andere in einen eigenen Faden.
            //
            // Der Grund ist eine Zahl aus der Erweiterung:
            //
            //     keepassClient.messageTimeout = 500;   // Millisekunden
            //
            // Über **eine** Verbindung laufen alle Anfragen. Wartet
            // `get-logins` auf eine Bestätigung des Nutzers, stünde jede
            // weitere Nachricht dahinter — auch die, die nach einer halben
            // Sekunde aufgibt. Der Nutzer sähe dann dauerhaft „Verbindung
            // nicht möglich", obwohl alles läuft und nur jemand auf ihn
            // wartet.
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
}

/// Schreibt eine Antwort — als Ganzes, damit sich zwei Fäden nicht ins
/// Gehege kommen.
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

/// Schreibt mit, was über den Kanal geht — nur mit `WKEEPASS_BROWSER_LOG=1`.
///
/// Absichtlich **ohne Inhalte**: Nur Aktion, Feldnamen und Längen. Was
/// verschlüsselt ankommt, bleibt verschlüsselt; ein Klartextwert darf hier
/// unter keinen Umständen landen, auch nicht versehentlich beim Suchen
/// eines Fehlers.
///
/// Das reicht trotzdem für fast jede Diagnose: Man sieht die Reihenfolge der
/// Aktionen, ob eine Antwort ausbleibt, und ob ein Feld fehlt.
fn trace(richtung: &str, message: &Value) {
    use std::sync::OnceLock;
    static AN: OnceLock<bool> = OnceLock::new();

    if !AN.get_or_init(|| std::env::var("WKEEPASS_BROWSER_LOG").is_ok_and(|v| v != "0")) {
        return;
    }

    let action = message.get("action").and_then(Value::as_str).unwrap_or("—");

    let felder: Vec<String> = message
        .as_object()
        .map(|o| {
            o.iter()
                .filter(|(name, _)| name.as_str() != "action")
                .map(|(name, value)| match value.as_str() {
                    // Base64-Felder werden mitgeprüft. Ein ungültiges Zeichen
                    // oder eine krumme Länge lässt die Erweiterung mit
                    // „invalid encoding" scheitern, ohne zu sagen welches Feld.
                    Some(text) if matches!(name.as_str(), "message" | "nonce" | "publicKey") => {
                        format!("{name}[{}{}]", text.len(), if ist_base64(text) { "" } else { " UNGÜLTIG" })
                    }
                    // Fehler werden im Klartext gezeigt. Sie stammen aus
                    // unserer eigenen Tabelle und enthalten nichts aus der
                    // Datenbank — und ohne sie ist ein Log kaum zu deuten:
                    // „errorCode[1]" heißt nur, dass die Zahl einstellig war.
                    Some(text) if matches!(name.as_str(), "error" | "errorCode") => {
                        format!("{name}={text}")
                    }
                    Some(text) => format!("{name}[{}]", text.len()),
                    None => name.clone(),
                })
                .collect()
        })
        .unwrap_or_default();

    eprintln!("[Browser] {richtung} {action}  {}", felder.join(" "));

    // Stufe 2 zeigt den Umschlag im Klartext. Der Inhalt bleibt verschlüsselt —
    // was hier steht, ist Schlüsseltext und Nonce, kein Geheimnis.
    if std::env::var("WKEEPASS_BROWSER_LOG").is_ok_and(|v| v == "2") {
        eprintln!("[Browser]   {}", serde_json::to_string(message).unwrap_or_default());
    }
}

/// Genau die Prüfung, die `nacl.util.decodeBase64` anstellt.
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
}

impl Connection {
    fn new() -> Self {
        Self { keys: KeyPair::generate(), session: None, client_id: None }
    }

    /// Nimmt eine Nachricht entgegen und liefert die Antwort.
    ///
    /// Läuft in einem eigenen Faden. Die Sperre auf der Verbindung wird
    /// deshalb nur kurz gehalten — zum Entschlüsseln und zum Verpacken.
    /// Dazwischen kann die Bearbeitung beliebig lange dauern, ohne andere
    /// Nachrichten derselben Verbindung aufzuhalten.
    fn process(
        shared: &std::sync::Arc<Mutex<Self>>,
        app: &tauri::AppHandle,
        message: &Value,
    ) -> Value {
        let action = message.get("action").and_then(Value::as_str).unwrap_or_default();

        // `triggerUnlock` steht **außen** an der Nachricht, nicht im
        // verschlüsselten Teil. Die Erweiterung setzt es, wenn der Nutzer
        // etwas angestoßen hat — etwa „Datenbank entsperren" in ihrem Menü.
        //
        // Hier darf **nicht gewartet** werden. Die Erweiterung hat für
        // `get-databasehash` eine kurze Frist; wer sie verstreichen lässt,
        // bekommt „5: Verbindung nicht möglich", und die verspätete Antwort
        // findet später keine Anfrage mehr. Deshalb geht die Anmeldemaske in
        // einem eigenen Faden auf, und diese Nachricht wird sofort
        // beantwortet.
        if message.get("triggerUnlock").and_then(Value::as_str) == Some("true") && !is_open(app) {
            let app = app.clone();
            std::thread::spawn(move || {
                let _ = await_unlocked(&app);
            });
        }

        // --- kurz sperren: entschlüsseln ---
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

        // --- ohne Sperre: die eigentliche Arbeit, die warten darf ---
        let result = Self::dispatch(shared, app, action, &inner);

        // --- kurz sperren: verpacken ---
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

    /// Verpackt eine Antwort — mit dem **erhöhten** Nonce.
    ///
    /// Nicht dasselbe wie in der Anfrage: Die Erweiterung zählt selbst hoch
    /// und vergleicht. Wer hier das gleiche Nonce zurückgibt, bekommt keinen
    /// Fehler zu sehen — die Erweiterung schweigt einfach.
    fn wrap(&self, action: &str, answer: &Value, request_nonce: &Nonce) -> Value {
        let Some(session) = self.session.as_ref() else {
            return error(action, code::CANNOT_DECRYPT_MESSAGE, "Kein Schlüsselaustausch erfolgt.");
        };

        let reply_nonce = protocol::increment_nonce(request_nonce);
        let reply_nonce_b64 = protocol::encode(&reply_nonce);

        // Das Nonce gehört **auch in den verschlüsselten Inhalt**, nicht nur
        // auf den Umschlag. Die Erweiterung prüft es dort nämlich noch einmal:
        //
        //     verifyDatabaseResponse(response, nonce) {
        //         if (!checkNonceLength(response.nonce)) …
        //         if (response.nonce !== nonce) …
        //
        //     checkNonceLength(nonce) {
        //         return nacl.util.decodeBase64(nonce).length === 24;
        //
        // Fehlt es innen, bekommt `decodeBase64` ein `undefined`, macht daraus
        // die Zeichenkette „undefined" — und die ist kein Base64. Heraus kommt
        // „TypeError: invalid encoding", ohne jeden Hinweis auf das fehlende
        // Feld. Fehlerantworten fielen nicht auf, weil sie nie entschlüsselt
        // werden.
        //
        // Innen und außen muss dasselbe stehen; die Erweiterung vergleicht.
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

        // Auch hier gilt schon das **erhöhte** Nonce, obwohl noch nichts
        // verschlüsselt ist. Die Erweiterung prüft in `verifyKeyResponse`
        // gegen `incrementedNonce`:
        //
        //     const reply = (response.nonce === nonce);
        //
        // Wer das Nonce der Anfrage zurückspiegelt, bekommt „Schlüsselaustausch
        // war nicht erfolgreich" — ohne Hinweis worauf.
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
            // Ohne offene Datenbank beantwortbar
            "get-databasehash" => Ok(json!({ "hash": database_hash(app)? })),
            "generate-password" => Ok(json!({
                "password": generate_password(),
                // Ältere Fassungen der Erweiterung lesen es aus `entries`.
                "entries": [{ "login": "", "password": generate_password() }],
            })),

            // Wiedererkennung
            "associate" => Self::associate(shared, app, inner),
            "test-associate" => Self::test_associate(shared, app, inner),

            // Alles Weitere setzt eine offene Datenbank voraus. Ist sie zu,
            // wird gewartet statt abgewiesen — sonst gibt die Erweiterung auf
            // und die Seite müsste neu geladen werden.
            _ => {
                await_unlocked(app)?;

                match action {
                    "get-logins" => Self::get_logins(shared, app, inner),
                    "set-login" => set_login(app, inner),
                    "get-totp" => get_totp(app, inner),
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
    /// Ohne diese Rückfrage könnte jede beliebige Website über die
    /// Erweiterung sämtliche Zugangsdaten abfragen. Der Dialog wird bewusst
    /// vom eigenen Fenster gezeichnet: Was der Browser zeichnet, kann eine
    /// Seite beeinflussen.
    fn get_logins(shared: &std::sync::Arc<Mutex<Self>>, app: &tauri::AppHandle, inner: &Value) -> Result<Value, Failure> {
        let url = inner
            .get("url")
            .and_then(Value::as_str)
            .ok_or_else(|| Failure(code::NO_URL_PROVIDED, "Keine Adresse angegeben.".into()))?;

        // Wohin das Formular abgeschickt wird. Weicht es von der besuchten
        // Adresse ab, gehört das in die Rückfrage — es ist das klassische
        // Merkmal einer untergeschobenen Anmeldemaske.
        let submit = inner.get("submitUrl").and_then(Value::as_str);

        let (host, path) = split_url(url)
            .ok_or_else(|| Failure(code::NO_URL_PROVIDED, "Adresse nicht lesbar.".into()))?;
        let client = client_id(shared);

        let candidates = matching_entries(app, &host, &path)?;
        if candidates.is_empty() {
            return Ok(json!({ "count": 0, "entries": [] }));
        }

        // Ein ausdrückliches Nein am Eintrag bleibt ein Nein. Solche
        // Vermerke legen wir selbst nicht mehr an — sie stammen aus
        // KeePassXC, und dort getroffene Entscheidungen zu übergehen wäre
        // dreist.
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

        let rp_id = options
            .get("rp")
            .and_then(|rp| rp.get("id").or_else(|| rp.get("name")))
            .and_then(Value::as_str)
            .or_else(|| inner.get("origin").and_then(Value::as_str).and_then(host_of_str))
            .ok_or_else(|| Failure(code::PASSKEYS_UNKNOWN_ERROR, "Kein Ziel angegeben.".into()))?
            .to_string();

        let user = options.get("user");
        let name = user
            .and_then(|u| u.get("name"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();

        let answer = ask_user(
            app,
            json!({
                "kind": "passkey-register",
                "client": client_id(shared),
                "host": rp_id,
                "login": name,
            }),
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

        let answer = ask_user(
            app,
            json!({
                "kind": "passkey-get",
                "client": client_id(shared),
                "host": rp_id,
            }),
        )?;
        if !answer.allow {
            return Err(Failure(code::PASSKEYS_REQUEST_CANCELED, "Anmeldung abgelehnt.".into()));
        }

        // Die Seite darf mehrere Kennungen anbieten — etwa einen Schlüssel
        // vom Telefon und einen vom Rechner. Nur die erste zu probieren
        // hieße: Steht unserer an zweiter Stelle, findet ihn niemand.
        //
        // Eine leere Liste heißt „nimm was du hast" — dann suchen wir allein
        // über die Gegenstelle.
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
    /// Der Schlüssel, der hier ankommt, ist **nicht** der Sitzungsschlüssel:
    /// Er dient allein der Wiedererkennung beim nächsten Mal.
    fn associate(shared: &std::sync::Arc<Mutex<Self>>, app: &tauri::AppHandle, inner: &Value) -> Result<Value, Failure> {
        let key = inner
            .get("idKey")
            .and_then(Value::as_str)
            .ok_or_else(|| Failure(code::ASSOCIATION_FAILED, "Kein Verknüpfungsschlüssel.".into()))?;

        // Den Namen vergibt der Nutzer; bis dahin nehmen wir einen sprechenden
        // Vorschlag. Eine Rückfrage gehört hier hin — noch offen.
        let name = inner
            .get("key")
            .and_then(Value::as_str)
            .map(|_| format!("WKeePass {}", short(key)))
            .unwrap_or_else(|| format!("Browser {}", short(key)));

        let state = app.state::<Vault>();
        let mut vault = state.lock().map_err(|_| Failure(0, "Kern blockiert.".into()))?;
        let db = vault.database_mut().map_err(|_| Failure(code::DATABASE_NOT_OPENED, "Datenbank ist zu.".into()))?;

        db.meta.custom_data.insert(
            format!("{ASSOCIATION_PREFIX}{name}"),
            keepass::db::CustomDataItem {
                value: Some(keepass::db::CustomDataValue::String(key.to_string())),
                last_modification_time: None,
            },
        );

        if let Ok(mut conn) = shared.lock() {
            conn.client_id = Some(name.clone());
        }

        let antwort = json!({ "id": name, "hash": database_hash_locked(db) });
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

        let state = app.state::<Vault>();
        let vault = state.lock().map_err(|_| Failure(0, "Kern blockiert.".into()))?;
        let db = vault.database().map_err(|_| Failure(code::DATABASE_NOT_OPENED, "Datenbank ist zu.".into()))?;

        let stored = db
            .meta
            .custom_data
            .get(&format!("{ASSOCIATION_PREFIX}{id}"))
            .and_then(|item| item.value.as_ref())
            .and_then(|value| match value {
                keepass::db::CustomDataValue::String(text) => Some(text.as_str()),
                _ => None,
            });

        if stored != Some(key) {
            return Err(Failure(code::ASSOCIATION_FAILED, "Dieser Browser ist nicht verknüpft.".into()));
        }

        if let Ok(mut conn) = shared.lock() {
            conn.client_id = Some(id.to_string());
        }
        Ok(json!({ "id": id, "hash": database_hash_locked(db) }))
    }
}

/// Baut die Hülle, die die Erweiterung um einen Passkey erwartet.
///
/// Der Weg durch die Erweiterung, Stück für Stück:
///
/// ```javascript
/// sendPasskeysResponse(ret.response, …)          // passkeys-inject.js
/// … = { publicKey: publicKey, fallback: … }      // passkeys-utils.js
/// createPublicKeyCredential(response.publicKey)  // passkeys.js
/// ```
///
/// Die mittlere Zeile ist der Haken: Die Erweiterung **legt die Hülle
/// `publicKey` selbst an**. Ihr Parameter heißt zwar so, ist aber schon der
/// fertige Ausweis. Wer sich vom Namen leiten lässt und die Hülle
/// mitliefert, schickt sie doppelt — die Seite bekommt dann einen Ausweis,
/// der nur ein Feld `publicKey` hat und keins der erwarteten:
///
/// ```text
/// { "response": {                    ← liest passkeys-inject.js als ret.response
///     "id", "type", "authenticatorAttachment",
///     "response": { … }              ← die eigentlichen WebAuthn-Daten
///   } }
/// ```
///
/// Eine Stufe zu viel oder zu wenig endet gleich: `undefined` und
/// „Authentication failed", ohne einen Hinweis worauf.
///
/// `rawId` bleibt weg — die Erweiterung rechnet es sich aus `id` aus. Und
/// `authenticatorAttachment: "platform"` heißt: Der Schlüssel liegt auf
/// diesem Gerät, nicht auf einem angesteckten Stick. Das trifft zu, er liegt
/// in der Datenbank.
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
/// Ohne das steht die Änderung nur im Arbeitsspeicher. Beim Verknüpfen fällt
/// das sofort auf: Der Browser gilt nach jedem Neustart wieder als
/// unbekannt, weil `test-associate` in einer frisch geladenen Datei nichts
/// findet — man müsste bei jedem Start erneut auf „Verbinden" drücken.
///
/// Läuft in einem eigenen Faden, und zwar aus einem harten Grund: Zum
/// Speichern wird der Schlüssel neu aus dem Master-Passwort abgeleitet, und
/// Argon2 braucht dafür eine knappe Sekunde. Die Erweiterung wartet aber nur
/// **500 ms** auf die Antwort. Erst antworten, dann speichern.
///
/// Der Faden nimmt sich das Schloss selbst; er wartet dabei, bis der
/// Aufrufer seins losgelassen hat.
fn persist(app: &tauri::AppHandle) {
    let app = app.clone();
    std::thread::spawn(move || {
        if let Err(err) = crate::database::commit(&app.state::<Vault>()) {
            // Das ist kein Diagnosekram, sondern verlorene Arbeit — deshalb
            // unabhängig von `WKEEPASS_BROWSER_LOG`.
            eprintln!("[Browser] Nicht gespeichert: {err}");
            let _ = app.emit("browser-save-failed", err);
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

/// Ein kurzer, lesbarer Anfang eines Schlüssels — für Anzeigenamen.
fn short(key: &str) -> String {
    key.chars().filter(|c| c.is_alphanumeric()).take(6).collect()
}

/// Kennzeichnet die offene Datenbank.
///
/// Die Erweiterung merkt daran, ob noch dieselbe Datei offen ist wie beim
/// letzten Mal. Der Wert muss nur stabil sein und sich zwischen Datenbanken
/// unterscheiden — geprüft wird er nirgends gegen.
fn database_hash(app: &tauri::AppHandle) -> Result<String, Failure> {
    let state = app.state::<Vault>();
    let vault = state.lock().map_err(|_| Failure(0, "Kern blockiert.".into()))?;
    let db = vault.database().map_err(|_| Failure(code::DATABASE_NOT_OPENED, "Datenbank ist zu.".into()))?;
    Ok(database_hash_locked(db))
}

fn database_hash_locked(db: &keepass::Database) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(db.root().id().uuid().to_string().as_bytes());
    hasher.update(db.meta.database_name.as_deref().unwrap_or_default().as_bytes());

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

/// Wie lange eine Legitimation nachwirkt.
///
/// Wer sich gerade ausgewiesen hat, soll nicht drei Formulare später erneut
/// gefragt werden. Eine Minute ist kurz genug, dass ein unbeaufsichtigter
/// Rechner nicht zum Selbstbedienungsladen wird, und lang genug für einen
/// zusammenhängenden Vorgang.
///
/// Gilt **nur** für die Legitimation. Eine ausdrückliche Rückfrage je Seite
/// wird nicht übersprungen — dort geht es um die Seite, nicht um dich.
const IDENTIFY_GRACE: std::time::Duration = std::time::Duration::from_secs(60);

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

/// Ist die letzte Legitimation noch frisch genug?
fn within_grace() -> bool {
    last_identified()
        .lock()
        .ok()
        .and_then(|at| *at)
        .is_some_and(|at| at.elapsed() < IDENTIFY_GRACE)
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

/// Parkt die Anfrage und wartet auf die Antwort aus dem Fenster.
fn ask_user(app: &tauri::AppHandle, mut details: Value) -> Result<Decision, Failure> {
    let mode = guard(app);

    // „Nichts" heißt nichts — kein Fenster, keine Frist, keine Verzögerung.
    if mode == Guard::Never {
        return Ok(Decision { allow: true });
    }

    // Gerade erst bestätigt? Dann nicht schon wieder fragen.
    //
    // Gilt für beide Stufen: Wer eben zugestimmt hat, sitzt noch am Rechner.
    // Ohne diese Frist wäre eine Anmeldemaske mit drei Feldern eine Tortur.
    //
    // Muss **vor** dem Eintragen stehen: Ein Eintrag, der nie beantwortet
    // wird, bliebe sonst in der Liste liegen und hielte das Rückfragefenster
    // offen.
    if within_grace() {
        return Ok(Decision { allow: true });
    }

    let id = format!("br{}", now_millis());
    let (tx, rx) = std::sync::mpsc::channel();

    details["id"] = json!(id);
    // `Never` ist oben schon weg — hier bleiben nur die beiden Stufen, die
    // das Fenster überhaupt zeichnen kann.
    details["guard"] = json!(match mode {
        Guard::Identify => "identify",
        _ => "confirm",
    });

    pending()
        .lock()
        .map_err(|_| Failure(0, "Rückfrage blockiert.".into()))?
        .insert(id.clone(), Parked { tx, details: details.clone() });

    open_request_window(app, ASK_HEIGHT);

    // Das Ereignis ist nur der schnelle Weg — es geht ins Leere, wenn das
    // Fenster seine Zuhörer noch nicht eingehängt hat. Verlassen wird sich
    // darauf nicht: Die Seite fragt beim Start selbst nach (`browser_pending`).
    let _ = app.emit("browser-request", details);

    let answer = rx.recv_timeout(CONSENT_TIMEOUT);

    // In jedem Fall aufräumen — sonst wüchse die Liste mit jeder Zeitüberschreitung.
    unpark(app, &id);

    // Keine Antwort heißt Nein. Alles andere wäre die falsche Voreinstellung.
    Ok(answer.unwrap_or(Decision { allow: false }))
}

/// Beantwortet eine geparkte Anfrage. Wird von der Oberfläche aufgerufen.
#[tauri::command]
pub fn browser_answer(id: String, allow: bool) -> Result<bool, String> {
    let Ok(mut map) = pending().lock() else {
        return Err("Rückfrage blockiert.".into());
    };

    match map.remove(&id) {
        Some(parked) => {
            let _ = parked.tx.send(Decision { allow });
            Ok(true)
        }
        // Schon abgelaufen oder doppelt beantwortet — kein Fehler.
        None => Ok(false),
    }
}

/// Was gerade auf eine Antwort wartet.
///
/// Das Rückfragefenster ruft das beim Start ab. Sich allein auf das Ereignis
/// zu verlassen wäre ein Wettlauf: Ein frisch gebautes Fenster lädt erst
/// seine Module, und was vorher gesendet wurde, ist verloren.
#[tauri::command]
pub fn browser_pending() -> Result<Option<Value>, String> {
    let map = pending().lock().map_err(|_| "Rückfrage blockiert.".to_string())?;

    // Die älteste zuerst — die wartet am längsten.
    Ok(map.values().map(|p| p.details.clone()).next())
}

/// Wartet, bis die Datenbank offen ist, und bittet darum.
///
/// Ein sofortiger Fehler wäre unbrauchbar: Die Erweiterung gäbe auf, und man
/// müsste die Seite neu laden, nachdem man entsperrt hat.
///
/// Gefragt wird im **kleinen Fenster**, nicht im Hauptfenster. Wer im
/// Browser vor einem Anmeldeformular steht, will nicht die ganze Anwendung
/// aufgehen sehen — und muss sie dafür auch nicht offen halten.
///
/// Entsperrt wird trotzdem in *unserem* Fenster; das ist der Punkt, an dem
/// nicht gerüttelt wird. Das Master-Passwort darf nicht durch Code wandern,
/// den eine Website beeinflusst.
///
/// Wer hier entsperrt, hat sich damit ausgewiesen: Die Oberfläche meldet das
/// als Legitimation, und die Rückfrage, die gleich darauf folgt, fällt in
/// die Schonfrist. Ein Vorgang, ein Dialog — nicht zweimal dasselbe.
fn await_unlocked(app: &tauri::AppHandle) -> Result<(), Failure> {
    if is_open(app) {
        return Ok(());
    }

    // Fragt schon jemand? Dann nicht ein zweites Mal — zwei Anmeldemasken
    // übereinander für dieselbe Datei sind sinnlos. Ein Formular mit mehreren
    // Feldern löst leicht mehrere Anfragen zugleich aus.
    let laeuft_schon = pending()
        .lock()
        .map(|m| m.values().any(|p| p.details.get("kind").and_then(Value::as_str) == Some("unlock")))
        .unwrap_or(false);

    let id = format!("br{}", now_millis());
    let (tx, rx) = std::sync::mpsc::channel();

    if !laeuft_schon {
        let details = json!({ "id": id, "kind": "unlock" });

        pending()
            .lock()
            .map_err(|_| Failure(0, "Rückfrage blockiert.".into()))?
            .insert(id.clone(), Parked { tx, details: details.clone() });

        open_request_window(app, UNLOCK_HEIGHT);
        let _ = app.emit("browser-request", details);

        // Steht das Hauptfenster ohnehin offen, soll es auch dort sichtbar
        // sein. Doppelt gefragt wird nicht: Wer dort entsperrt, beendet das
        // Warten unten genauso.
        let _ = app.emit("browser-needs-unlock", json!({}));
    }

    let deadline = std::time::Instant::now() + UNLOCK_TIMEOUT;
    let mut ergebnis = Err(Failure(code::DATABASE_NOT_OPENED, "Die Datenbank blieb gesperrt.".into()));

    while std::time::Instant::now() < deadline {
        match rx.recv_timeout(std::time::Duration::from_millis(200)) {
            // Das kleine Fenster meldet sich, wenn es fertig ist.
            Ok(entscheidung) => {
                ergebnis = match entscheidung.allow && is_open(app) {
                    true => Ok(()),
                    false => Err(Failure(code::DATABASE_NOT_OPENED, "Entsperren abgebrochen.".into())),
                };
                break;
            }
            // Kein Ton — dann selbst nachsehen. So endet das Warten auch,
            // wenn im Hauptfenster entsperrt wurde.
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
    // die nächste.
    let leer = pending().lock().map(|m| m.is_empty()).unwrap_or(true);
    if leer {
        if let Some(window) = app.get_webview_window(REQUEST_WINDOW) {
            let _ = window.close();
        }
    }
}

fn is_open(app: &tauri::AppHandle) -> bool {
    app.state::<Vault>().lock().is_ok_and(|v| v.db.is_some())
}

/// Öffnet das kleine Fenster für eine Rückfrage — über allem anderen.
///
/// Bewusst **nicht** das Hauptfenster: Wer im Browser ein Anmeldeformular
/// ausfüllt, will nicht in eine ganze Anwendung geworfen werden. Ein
/// eigenes, kleines Fenster mittig über dem Browser stört am wenigsten und
/// ist zugleich unmissverständlich unseres.
///
/// Dass es *unser* Fenster ist und nicht etwas, das die Website zeichnet,
/// ist der eigentliche Punkt: Eine Bestätigung, die im Browser entstünde,
/// könnte eine Seite nachbauen.
fn open_request_window(app: &tauri::AppHandle, hoehe: f64) {
    // Schon offen? Dann nur nach vorn holen — sonst stapeln sich Fenster,
    // wenn eine Seite mehrere Formulare hat.
    if let Some(window) = app.get_webview_window(REQUEST_WINDOW) {
        // Die Höhe passt sich an: Eine Anmeldemaske braucht mehr Platz als
        // ein Ja/Nein. Ein Fenster, das für beides reicht, ist für das eine
        // zu leer und für das andere zu eng.
        let _ = window.set_size(tauri::LogicalSize::new(WINDOW_WIDTH, hoehe));
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
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

    // Obenauf *und* mit dem Eingabezeiger: Ein Fenster, das zwar oben liegt,
    // aber die Tastatur nicht bekommt, zwingt zu einem Klick, bevor man
    // tippen kann.
    if let Ok(window) = &built {
        let _ = window.set_focus();
    }

    // Klappt das nicht — etwa weil kein Fenstersystem da ist —, bleibt das
    // Hauptfenster als Rückfallweg.
    if built.is_err() {
        if let Some(window) = app.get_webview_window("main") {
            let _ = window.unminimize();
            let _ = window.show();
            let _ = window.set_focus();
        }
    }
}

/// Der Name des Rückfragefensters.
const REQUEST_WINDOW: &str = "browser-request";

const WINDOW_WIDTH: f64 = 440.0;
/// Reicht für Ja/Nein oder ein einzelnes Feld.
const ASK_HEIGHT: f64 = 340.0;
/// Reicht zusätzlich für Dateiname, PIN und Master-Passwort.
const UNLOCK_HEIGHT: f64 = 440.0;

/// Holt das Hauptfenster nach vorn.
#[allow(dead_code)]
fn bring_to_front(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
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
/// Dieselbe Form wie bei KeePassXC — wer die Datei dort öffnet, findet
/// dieselben Freigaben wieder.
const DECISION_PREFIX: &str = "KP_BROWSER_";

/// Der Rechnername einer Adresse, ohne Anmeldedaten, Port und Pfad.
fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let rest = rest.split(['/', '?', '#']).next()?;
    let rest = rest.rsplit_once('@').map(|(_, r)| r).unwrap_or(rest);
    let host = rest.split(':').next()?.trim().to_ascii_lowercase();

    (!host.is_empty()).then_some(host)
}

/// Wie `host_of`, aber für Stellen, die einen geliehenen Wert brauchen.
fn host_of_str(url: &str) -> Option<&str> {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let rest = rest.split(['/', '?', '#']).next()?;
    let host = rest.split(':').next()?;

    (!host.is_empty()).then_some(host)
}

/// Rechnername und Pfad einer Adresse, ohne Anmeldedaten, Port und Anhängsel.
fn split_url(url: &str) -> Option<(String, Vec<String>)> {
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
fn match_score(entry_url: &str, wanted_host: &str, wanted_path: &[String]) -> Option<u32> {
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
        // Was im Papierkorb liegt, wird nicht mehr angeboten.
        if bin.is_some_and(|b| entry.parent().id() == b) {
            continue;
        }

        // Passkeys gehören nicht in die Passwortauswahl.
        //
        // Sie tragen zwar Adresse und Benutzernamen und passen damit auf die
        // Anfrage, haben aber gar kein Passwort. In der Liste der Erweiterung
        // stünden sie als Wahlmöglichkeit, die beim Anklicken ein leeres Feld
        // hinterlässt. Ihr Weg ist `passkeys-get`, nicht `get-logins`.
        if entry.get(crate::passkey::F_ID).is_some() {
            continue;
        }

        let urls = std::iter::once(entry.get_url().unwrap_or_default().to_string())
            .chain(
                entry
                    .fields
                    .iter()
                    .filter(|(name, _)| name.starts_with("KP_ADDITIONAL_URL"))
                    .map(|(_, value)| value.to_string()),
            )
            .collect::<Vec<_>>();

        // Der beste Treffer unter allen Adressen des Eintrags zählt.
        let Some(score) = urls.iter().filter_map(|u| match_score(u, host, path)).max() else {
            continue;
        };

        let decision = entry
            .custom_data
            .get(&format!("{DECISION_PREFIX}{host}"))
            .and_then(|item| item.value.as_ref())
            .and_then(|value| match value {
                keepass::db::CustomDataValue::String(text) => Some(text == "true"),
                _ => None,
            });

        // Ein ausdrückliches Nein bleibt ein Nein — nicht erneut fragen.
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

    // Genauester zuerst. Die Erweiterung zeigt die Liste in dieser
    // Reihenfolge an, und oben steht dann, was am ehesten gemeint ist.
    out.sort_by(|a, b| b.score.cmp(&a.score));

    Ok(out)
}

/// Der gerade gültige TOTP-Code eines Eintrags, falls einer hinterlegt ist.
fn current_totp(raw: &str) -> Option<String> {
    let uri = if raw.starts_with("otpauth://") {
        raw.to_string()
    } else {
        format!(
            "otpauth://totp/WKeePass?secret={}&digits=6&period=30&algorithm=SHA1",
            raw.trim().replace(' ', "")
        )
    };

    let totp: keepass::db::TOTP = uri.parse().ok()?;
    totp.value_now().ok().map(|code| code.code)
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

    persist(app);
    Ok(json!({ "count": 1, "entries": [] }))
}

/// Der gerade gültige TOTP-Code eines Eintrags.
fn get_totp(app: &tauri::AppHandle, inner: &Value) -> Result<Value, Failure> {
    let uuid = inner
        .get("uuid")
        .and_then(Value::as_str)
        .ok_or_else(|| Failure(code::NO_VALID_UUID_PROVIDED, "Kein Eintrag angegeben.".into()))?;

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
    app.state::<Vault>()
        .lock()
        .map_err(|_| Failure(0, "Kern blockiert.".into()))?
        .clear();

    let _ = app.emit("vault-locked", "Über die Browser-Erweiterung gesperrt.");
    Ok(json!({}))
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
    // Fenster: erst in den Papierkorb, endgültig erst beim zweiten Mal.
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
/// Zeichen, die sich beim Abschreiben verwechseln lassen, bleiben draußen —
/// null und O, eins und l. Ein Passwort aus dem Manager wird zwar meist
/// eingefügt, aber eben nicht immer.
fn generate_password() -> String {
    use rand_core::RngCore;

    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789\
                              !#$%&*+-=?@^_";
    const LENGTH: usize = 24;

    let mut raw = [0u8; LENGTH];
    rand_core::OsRng.fill_bytes(&mut raw);

    // Der Rest der Division verzerrt die Verteilung leicht, weil 256 kein
    // Vielfaches der Alphabetlänge ist. Bei dieser Größe ist der Unterschied
    // verschwindend; wer es genau will, verwürfe die überzähligen Werte.
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
        // „Von uns eingetragen" heißt: Das Manifest zeigt auf unser Programm.
        // Zeigt es woandershin, gehört es KeePassXC.
        let ours = program.as_ref().is_some_and(|p| route::points_at(&target.file(), p));

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
        listening: socket.exists(),
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
/// Danach fragt er beim nächsten Mal wieder um Erlaubnis. Die einzelnen
/// Freigaben je Eintrag bleiben davon unberührt — die hängen am Eintrag.
#[tauri::command]
pub fn browser_forget(state: tauri::State<'_, Vault>, name: String) -> Result<bool, String> {
    let mut vault = state.lock().map_err(|_| "Kern blockiert.".to_string())?;
    let db = vault.database_mut()?;

    Ok(db.meta.custom_data.remove(&format!("{ASSOCIATION_PREFIX}{name}")).is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keepass_extension::protocol::{self, KeyPair};

    /// Genau die Prüfung aus `nacl-util.min.js` der Erweiterung.
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

    /// Baut eine Verbindung mit fertigem Schlüsseltausch — wie nach dem
    /// ersten Kontakt mit der Erweiterung.
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

        // … und beide Felder müssen ihre Base64-Prüfung bestehen.
        assert!(ist_gueltiges_base64(message), "message: {message}");
        assert!(ist_gueltiges_base64(nonce), "nonce: {nonce}");

        // Das Nonce muss das erhöhte sein.
        assert_eq!(nonce, protocol::encode(&protocol::increment_nonce(&anfrage_nonce)));

        // Und die Gegenstelle muss es aufbekommen.
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

    /// Genau **eine** Hülle um den Ausweis — die zweite legt die Erweiterung
    /// selbst an (`sendPasskeysResponse` in passkeys-utils.js). Eine Stufe zu
    /// viel oder zu wenig endet gleich: „Authentication failed".
    #[test]
    fn passkey_antwort_hat_die_huelle_der_erweiterung() {
        let antwort = json!({ "response": credential("abc", json!({
            "clientDataJSON": "eyJ9",
            "authenticatorData": "AAA",
            "signature": "MEQ",
            "userHandle": Value::Null,
        })) });

        // Das hier ist, was `createPublicKeyCredential` zu sehen bekommt.
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
        // Umgekehrt gilt nicht: Ein Eintrag für die Unterdomain zählt nicht
        // für die Hauptdomain — sonst käme man von example.com an alles.
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

    /// `verifyDatabaseResponse` prüft das Nonce **im Inhalt**, nicht nur auf
    /// dem Umschlag. Fehlt es dort, scheitert die Erweiterung mit
    /// „invalid encoding" — an einer Stelle, die nichts mit Kodierung zu tun
    /// hat. Der Test hält genau das fest.
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

        // checkNonceLength(response.nonce) — 24 Bytes, sonst Ausnahme
        let innen = inhalt["nonce"].as_str().expect("kein nonce im Inhalt");
        assert_eq!(protocol::decode(innen).unwrap().len(), protocol::NONCE_LEN);

        // response.nonce !== nonce — innen und außen müssen gleich sein
        assert_eq!(innen, erwartet);
        assert_eq!(verpackt["nonce"].as_str().unwrap(), erwartet);
    }
}

/* =========================================================
   Wie streng wird gefragt?
   ========================================================= */

/// Was vor der Herausgabe von Zugangsdaten verlangt wird.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum Guard {
    /// Gar nichts. Der verknüpfte Browser bekommt, was er anfragt.
    ///
    /// Wer alleine an seinem Rechner sitzt, will nicht bei jedem
    /// Anmeldeformular etwas wegklicken. Der Browser hat sich mit seinem
    /// Schlüssel ausgewiesen, und die Datenbank ist offen — beides hat der
    /// Nutzer selbst so eingerichtet.
    ///
    /// Nur eben nicht als Voreinstellung: Der Schlüssel liegt auf demselben
    /// Rechner, an dem auch jemand anderes sitzen könnte.
    Never,
    /// Nur ein Knopfdruck: Abbrechen oder Übernehmen. Kein Nachweis.
    Confirm,
    /// PIN, Master-Passwort oder Fingerabdruck. Die Voreinstellung.
    Identify,
}

/// Liest die Einstellung `browser.guard`.
///
/// Fehlt sie oder ist sie unlesbar, gilt `Identify` — im Zweifel das
/// Strengere. Eine unlesbare Datei darf nicht dazu führen, dass Passwörter
/// leichter herausgehen als vorgesehen.
fn guard(app: &tauri::AppHandle) -> Guard {
    match crate::settings::value(app, "browser.guard").as_ref().and_then(Value::as_str) {
        Some("never") => Guard::Never,
        Some("confirm") => Guard::Confirm,
        _ => Guard::Identify,
    }
}
