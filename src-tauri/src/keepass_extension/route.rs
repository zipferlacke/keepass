//! Der Verteiler: wo unser Programm liegt, wo der Kanal liegt, und das
//! Sprachrohr dazwischen.
//!
//! Drei Aufgaben, die zusammengehören, weil sie alle davon handeln, **wo**
//! etwas ist:
//!
//!   1. die Manifest-Dateien, über die ein Browser uns überhaupt findet
//!   2. der Pfad des Kanals, je Betriebssystem verschieden
//!   3. das Sprachrohr, das der Browser startet und das an diesen Kanal
//!      weiterreicht — samt Rückfallweg zu KeePassXC
//!
//! Was über den Kanal *gesprochen* wird, steht nebenan in `api.rs`.
//!
//! # Wie ein Browser eine Anwendung auf dem Rechner findet
//!
//! Gar nicht direkt. Eine Erweiterung darf keine Sockets öffnen und keine
//! Programme starten. Der einzige erlaubte Weg heißt *Native Messaging*:
//! Die Erweiterung nennt einen **Namen**, der Browser schlägt ihn in einer
//! JSON-Datei nach, und darin steht, welches Programm zu starten ist.
//!
//! ```text
//! Erweiterung sagt: "org.keepassxc.keepassxc_browser"
//!         │
//!         ▼
//! ~/.mozilla/native-messaging-hosts/org.keepassxc.keepassxc_browser.json
//!         │   { "path": "/pfad/zu/wkeepass", "type": "stdio" }
//!         ▼
//! Browser startet dieses Programm und spricht über stdin/stdout mit ihm
//! ```
//!
//! Der **Name** ist von der Erweiterung vorgegeben und nicht zu ändern. Was
//! hinter ihm steckt, bestimmen wir — es ist eine Datei im Heimatverzeichnis,
//! und die schreiben wir selbst. Genauso macht es KeePassXC, wenn man dort
//! die Browser-Integration einschaltet.
//!
//! # Warum die Datei auf unser eigenes Programm zeigt
//!
//! Der Browser startet das Programm selbst, immer wieder, ohne Fenster, und
//! beendet es danach. Die laufende Anwendung mit der offenen Datenbank kann
//! das nicht sein. Also zeigt die Datei auf dieselbe ausführbare Datei, die
//! sich beim Start anhand der Argumente entscheidet: als Sprachrohr arbeiten
//! oder das Fenster öffnen (siehe `run_proxy` weiter unten).
//!
//! KeePassXC macht das übrigens genauso — deren Manifest zeigt ebenfalls auf
//! die Anwendung selbst, nicht auf ein eigenes Vermittlerprogramm.
//!
//! # Die Falle
//!
//! Firefox und Chromium benennen die Zugriffsliste **verschieden**:
//!
//! ```json
//! "allowed_extensions": ["keepassxc-browser@keepassxc.org"]   // Firefox
//! "allowed_origins":    ["chrome-extension://<Kennung>/"]     // Chromium
//! ```
//!
//! Steht der falsche Schlüssel darin, verweigert der Browser wortlos. Die
//! Kennungen unterscheiden sich zudem je Store.
//!
//! Deshalb: Liegt in einem Verzeichnis schon das Manifest von KeePassXC,
//! übernehmen wir dessen Zugriffsliste **unverändert** und tauschen nur den
//! Pfad. Das bleibt richtig, auch wenn neue Kennungen dazukommen.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

/// Der Name, unter dem die Erweiterung sucht. Nicht änderbar.
pub const HOST_NAME: &str = "org.keepassxc.keepassxc_browser";

/// Zugriffsliste für Firefox, falls keine Vorlage zu finden ist.
const FIREFOX_EXTENSIONS: &[&str] = &["keepassxc-browser@keepassxc.org"];

/// Zugriffsliste für Chromium, falls keine Vorlage zu finden ist.
/// Erste Kennung: Edge-Store, zweite: Chrome Web Store.
const CHROMIUM_ORIGINS: &[&str] = &[
    "chrome-extension://pdffhmdngciaglkoonimfcmckehcpafo/",
    "chrome-extension://oboonakemofpalcgghocfoadofidjkkk/",
];

/// Welche Art von Zugriffsliste ein Browser erwartet.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Flavour {
    Firefox,
    Chromium,
}

/// Ein Browser und der Ort, an dem er nachschlägt.
#[derive(Debug)]
pub struct Target {
    pub name: &'static str,
    pub flavour: Flavour,
    pub dir: PathBuf,
}

impl Target {
    pub fn file(&self) -> PathBuf {
        self.dir.join(format!("{HOST_NAME}.json"))
    }

    pub fn installed(&self) -> bool {
        // Das Elternverzeichnis ist der Beleg: Es existiert nur, wenn der
        // Browser schon einmal gelaufen ist. Wir legen es nicht selbst an —
        // sonst schriebe man Manifeste für Browser, die es nicht gibt.
        self.dir.parent().is_some_and(|p| p.is_dir())
    }
}

/// Alle Browser, die auf diesem Rechner in Frage kommen.
///
/// Zurück kommt jeder bekannte Ort; ob er tatsächlich gilt, sagt
/// `Target::installed`.
pub fn targets() -> Vec<Target> {
    let Some(home) = home_dir() else { return Vec::new() };
    let mut out = Vec::new();

    for (name, flavour, relative) in LOCATIONS {
        out.push(Target {
            name,
            flavour: *flavour,
            dir: home.join(relative),
        });
    }

    // Flatpak spiegelt dieselben Pfade unter ~/.var/app/<Kennung>/ —
    // dieselbe Erweiterung, anderer Ablageort.
    for (name, flavour, id, relative) in FLATPAK_LOCATIONS {
        out.push(Target {
            name,
            flavour: *flavour,
            dir: home.join(".var/app").join(id).join(relative),
        });
    }

    out
}

/// Ablageorte im Heimatverzeichnis. Linux und macOS trennen sich hier, weil
/// die Browser dort andere Verzeichnisnamen benutzen.
#[cfg(not(target_os = "macos"))]
const LOCATIONS: &[(&str, Flavour, &str)] = &[
    ("Firefox", Flavour::Firefox, ".mozilla/native-messaging-hosts"),
    ("LibreWolf", Flavour::Firefox, ".librewolf/native-messaging-hosts"),
    ("Waterfox", Flavour::Firefox, ".waterfox/native-messaging-hosts"),
    ("Zen", Flavour::Firefox, ".zen/native-messaging-hosts"),
    ("Chrome", Flavour::Chromium, ".config/google-chrome/NativeMessagingHosts"),
    ("Chrome Beta", Flavour::Chromium, ".config/google-chrome-beta/NativeMessagingHosts"),
    ("Chromium", Flavour::Chromium, ".config/chromium/NativeMessagingHosts"),
    ("Brave", Flavour::Chromium, ".config/BraveSoftware/Brave-Browser/NativeMessagingHosts"),
    ("Vivaldi", Flavour::Chromium, ".config/vivaldi/NativeMessagingHosts"),
    ("Edge", Flavour::Chromium, ".config/microsoft-edge/NativeMessagingHosts"),
    ("Opera", Flavour::Chromium, ".config/opera/NativeMessagingHosts"),
];

#[cfg(target_os = "macos")]
const LOCATIONS: &[(&str, Flavour, &str)] = &[
    ("Firefox", Flavour::Firefox, "Library/Application Support/Mozilla/NativeMessagingHosts"),
    ("LibreWolf", Flavour::Firefox, "Library/Application Support/LibreWolf/NativeMessagingHosts"),
    ("Chrome", Flavour::Chromium, "Library/Application Support/Google/Chrome/NativeMessagingHosts"),
    ("Chromium", Flavour::Chromium, "Library/Application Support/Chromium/NativeMessagingHosts"),
    ("Brave", Flavour::Chromium, "Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts"),
    ("Vivaldi", Flavour::Chromium, "Library/Application Support/Vivaldi/NativeMessagingHosts"),
    ("Edge", Flavour::Chromium, "Library/Application Support/Microsoft Edge/NativeMessagingHosts"),
];

#[cfg(not(target_os = "macos"))]
const FLATPAK_LOCATIONS: &[(&str, Flavour, &str, &str)] = &[
    ("Firefox (Flatpak)", Flavour::Firefox, "org.mozilla.firefox", ".mozilla/native-messaging-hosts"),
    ("Chrome (Flatpak)", Flavour::Chromium, "com.google.Chrome", "config/google-chrome/NativeMessagingHosts"),
    ("Chromium (Flatpak)", Flavour::Chromium, "org.chromium.Chromium", "config/chromium/NativeMessagingHosts"),
    ("Brave (Flatpak)", Flavour::Chromium, "com.brave.Browser", "config/BraveSoftware/Brave-Browser/NativeMessagingHosts"),
    ("Vivaldi (Flatpak)", Flavour::Chromium, "com.vivaldi.Vivaldi", "config/vivaldi/NativeMessagingHosts"),
];

#[cfg(target_os = "macos")]
const FLATPAK_LOCATIONS: &[(&str, Flavour, &str, &str)] = &[];

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// Baut den Inhalt der Manifest-Datei.
///
/// `vorlage` ist ein bereits vorhandenes Manifest — üblicherweise das von
/// KeePassXC. Ist eines da, wird dessen Zugriffsliste übernommen; sonst
/// greift die mitgelieferte.
fn build(flavour: Flavour, program: &Path, vorlage: Option<&Value>) -> Value {
    let mut manifest = json!({
        "name": HOST_NAME,
        "description": "WKeePass — Anbindung für keepassxc-browser",
        "path": program.to_string_lossy(),
        "type": "stdio",
    });

    let key = match flavour {
        Flavour::Firefox => "allowed_extensions",
        Flavour::Chromium => "allowed_origins",
    };

    let liste = vorlage
        .and_then(|v| v.get(key))
        .filter(|v| v.as_array().is_some_and(|a| !a.is_empty()))
        .cloned()
        .unwrap_or_else(|| match flavour {
            Flavour::Firefox => json!(FIREFOX_EXTENSIONS),
            Flavour::Chromium => json!(CHROMIUM_ORIGINS),
        });

    manifest[key] = liste;
    manifest
}

/// Liest ein vorhandenes Manifest, wenn es lesbar und gültig ist.
fn read(path: &Path) -> Option<Value> {
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

/// Was beim Ein- oder Ausschalten mit einem Browser geschehen ist.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Outcome {
    pub browser: String,
    pub path: String,
    pub ok: bool,
    pub note: Option<String>,
}

/// Schreibt das Manifest für alle eingerichteten Browser.
///
/// `program` ist der Pfad zu unserer eigenen ausführbaren Datei.
pub fn install(program: &Path) -> Vec<Outcome> {
    let mut out = Vec::new();

    for target in targets().into_iter().filter(Target::installed) {
        let file = target.file();

        // Ein fremdes Manifest ist kein Hindernis, sondern die beste
        // Vorlage: Es enthält die aktuell gültigen Kennungen des Stores.
        let vorlage = read(&file);
        let manifest = build(target.flavour, program, vorlage.as_ref());

        let result = std::fs::create_dir_all(&target.dir).and_then(|()| {
            std::fs::write(&file, serde_json::to_string_pretty(&manifest).unwrap_or_default())
        });

        out.push(Outcome {
            browser: target.name.to_string(),
            path: file.to_string_lossy().to_string(),
            ok: result.is_ok(),
            note: result.err().map(|e| e.to_string()),
        });
    }

    out
}

/// Nimmt die Manifeste wieder zurück.
///
/// Entfernt wird **nur**, was auf unser Programm zeigt. Ein fremdes Manifest
/// — etwa das von KeePassXC — bleibt unangetastet; wir haben es nicht
/// angelegt und löschen es nicht.
pub fn uninstall(program: &Path) -> Vec<Outcome> {
    let mut out = Vec::new();

    for target in targets() {
        let file = target.file();
        if !file.is_file() {
            continue;
        }

        let ours = read(&file)
            .and_then(|v| v.get("path").and_then(Value::as_str).map(str::to_string))
            .is_some_and(|p| Path::new(&p) == program);

        if !ours {
            continue;
        }

        let result = std::fs::remove_file(&file);
        out.push(Outcome {
            browser: target.name.to_string(),
            path: file.to_string_lossy().to_string(),
            ok: result.is_ok(),
            note: result.err().map(|e| e.to_string()),
        });
    }

    out
}

/// Wo unsere eigene ausführbare Datei liegt.
pub fn program_path() -> Result<PathBuf, String> {
    std::env::current_exe().map_err(|e| format!("Eigener Pfad nicht ermittelbar: {e}"))
}

/* =========================================================
   Wo der Kanal liegt
   ========================================================= */

/// Der Name des Kanals — bei uns bewusst ein anderer als bei KeePassXC.
///
/// Lauschten beide auf demselben Pfad, bekäme ihn das zuerst gestartete
/// Programm und das andere bliebe stumm. Mit einem eigenen Pfad laufen beide
/// nebeneinander, und das Sprachrohr entscheidet, wer gefragt wird.
const CHANNEL: &str = "de.wuefl.wkeepass.BrowserServer";

/// Der Pfad, auf dem **wir** lauschen.
///
/// Unter Linux und macOS ein Unix-Socket, unter Windows eine benannte Pipe.
/// Bevorzugt wird das Laufzeitverzeichnis des Benutzers: Es gehört ihm
/// allein, liegt im Arbeitsspeicher und wird beim Abmelden geleert. Erst
/// wenn es das nicht gibt, weichen wir nach `/tmp` aus.
pub fn socket_path() -> PathBuf {
    #[cfg(windows)]
    {
        return PathBuf::from(format!(r"\\.\pipe\{CHANNEL}"));
    }

    #[cfg(not(windows))]
    {
        if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
            return PathBuf::from(dir).join(CHANNEL);
        }
        // macOS kennt XDG_RUNTIME_DIR nicht, hat aber ein eigenes
        // benutzergebundenes Verzeichnis.
        if let Some(dir) = std::env::var_os("TMPDIR") {
            return PathBuf::from(dir).join(CHANNEL);
        }
        std::env::temp_dir().join(CHANNEL)
    }
}

/// Die Pfade, auf denen **KeePassXC** lauscht — für den Rückfallweg.
///
/// Mehrere, weil die Fassung als Flatpak ihren Kanal eine Ebene tiefer legt
/// und ältere Fassungen nach `/tmp` auswichen. Genommen wird der erste, der
/// tatsächlich da ist.
pub fn keepassxc_paths() -> Vec<PathBuf> {
    const NAME: &str = "org.keepassxc.KeePassXC.BrowserServer";

    #[cfg(windows)]
    {
        let user = std::env::var("USERNAME").unwrap_or_default();
        return vec![PathBuf::from(format!(r"\\.\pipe\keepassxc\{user}\{NAME}"))];
    }

    #[cfg(not(windows))]
    {
        let mut out = Vec::new();

        if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
            let dir = PathBuf::from(dir);
            // Die Flatpak-Fassung legt ihren Kanal unter app/<Kennung>/ ab.
            out.push(dir.join("app/org.keepassxc.KeePassXC").join(NAME));
            out.push(dir.join(NAME));
        }
        if let Some(dir) = std::env::var_os("TMPDIR") {
            out.push(PathBuf::from(dir).join(NAME));
        }
        out.push(PathBuf::from("/tmp").join(NAME));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firefox_und_chromium_bekommen_verschiedene_schluessel() {
        let program = Path::new("/usr/bin/wkeepass");

        let ff = build(Flavour::Firefox, program, None);
        assert!(ff.get("allowed_extensions").is_some());
        assert!(ff.get("allowed_origins").is_none(), "Firefox kennt allowed_origins nicht");

        let cr = build(Flavour::Chromium, program, None);
        assert!(cr.get("allowed_origins").is_some());
        assert!(cr.get("allowed_extensions").is_none(), "Chromium kennt allowed_extensions nicht");
    }

    #[test]
    fn der_name_bleibt_der_vorgegebene() {
        let m = build(Flavour::Firefox, Path::new("/usr/bin/wkeepass"), None);
        assert_eq!(m["name"], HOST_NAME);
        assert_eq!(m["type"], "stdio");
        assert_eq!(m["path"], "/usr/bin/wkeepass");
    }

    /// Der Kern der Sache: Eine vorhandene Zugriffsliste wird übernommen,
    /// damit neue Store-Kennungen nicht verlorengehen.
    #[test]
    fn vorhandene_zugriffsliste_wird_uebernommen() {
        let vorlage = json!({
            "allowed_origins": ["chrome-extension://neueKennung/"],
            "path": "/var/lib/flatpak/exports/bin/org.keepassxc.KeePassXC"
        });

        let m = build(Flavour::Chromium, Path::new("/usr/bin/wkeepass"), Some(&vorlage));

        assert_eq!(m["allowed_origins"][0], "chrome-extension://neueKennung/");
        assert_eq!(m["path"], "/usr/bin/wkeepass", "der Pfad muss unserer sein");
    }

    #[test]
    fn leere_vorlage_faellt_auf_die_mitgelieferte_liste_zurueck() {
        let vorlage = json!({ "allowed_origins": [] });
        let m = build(Flavour::Chromium, Path::new("/usr/bin/wkeepass"), Some(&vorlage));

        assert_eq!(m["allowed_origins"].as_array().unwrap().len(), CHROMIUM_ORIGINS.len());
    }

    #[test]
    fn jeder_ort_endet_auf_der_erwarteten_datei() {
        for target in targets() {
            assert!(
                target.file().ends_with(format!("{HOST_NAME}.json")),
                "{} zeigt auf {}", target.name, target.file().display()
            );
        }
    }
}

/* =========================================================
   Das Sprachrohr
   ---------------------------------------------------------
   Dieser Teil läuft in einem eigenen, kurzlebigen Prozess: Der Browser
   startet ihn, schiebt Nachrichten hinein und beendet ihn wieder. Er kennt
   die Datenbank nicht und sieht keinen einzigen Klartextwert — er reicht
   Bytes weiter.
   ========================================================= */

/// Erkennt, ob wir vom Browser gestartet wurden.
///
/// Beim Aufruf über Native Messaging übergibt der Browser Argumente, die
/// sonst nie auftauchen: Firefox den Pfad des Manifests und die Kennung der
/// Erweiterung, Chromium die Herkunft als `chrome-extension://…`. Findet
/// sich eines davon, arbeiten wir als Sprachrohr statt ein Fenster zu
/// öffnen.
pub fn started_by_browser() -> bool {
    std::env::args().skip(1).any(|arg| {
        arg.starts_with("chrome-extension://")
            || arg.contains(HOST_NAME)
            || arg.ends_with("@keepassxc.org")
    })
}

/// Wie lange nach einem selbst gestarteten Fenster gewartet wird.
const STARTUP_WAIT: std::time::Duration = std::time::Duration::from_secs(20);

/// Führt das Sprachrohr aus und kehrt erst zurück, wenn der Browser geht.
///
/// Die Suche nach der Gegenstelle in drei Schritten:
///
///   1. Läuft WKeePass? Dann dorthin.
///   2. Sonst WKeePass starten und warten — das ist der Fall „App war zu".
///   3. Klappt auch das nicht, an KeePassXC weiterreichen. So bleibt die
///      Erweiterung benutzbar, wenn unsere Anbindung abgeschaltet ist.
pub fn run_proxy() {
    let stream = match connect_anywhere() {
        Some(stream) => stream,
        None => {
            // Ohne Gegenstelle bleibt nur, sich sauber zu beenden. Eine
            // Fehlermeldung auf stdout würde der Browser als Nachricht
            // deuten und daran ersticken.
            eprintln!("WKeePass: keine Gegenstelle erreichbar");
            return;
        }
    };

    pump(stream);
}

#[cfg(not(windows))]
fn connect_anywhere() -> Option<std::os::unix::net::UnixStream> {
    use std::os::unix::net::UnixStream;

    let ours = socket_path();

    if let Ok(stream) = UnixStream::connect(&ours) {
        return Some(stream);
    }

    // Beim Entwickeln bewusst **nicht** starten.
    //
    // Eine Entwicklungsfassung holt ihre Oberfläche vom Server aus
    // `beforeDevCommand`. Startet das Sprachrohr eine zweite Ausgabe davon,
    // während `cargo tauri dev` gerade übersetzt oder gar nicht läuft, geht
    // ein Fenster mit „Could not connect to localhost" auf — verwirrend und
    // ohne Nutzen, denn die Datenbank ist ja im ersten Fenster offen.
    //
    // In der gebauten Fassung steckt die Oberfläche im Programm; dort ist
    // das Starten genau richtig und der eigentliche Zweck.
    if !cfg!(debug_assertions) {
        if let Some(stream) = start_app_and_wait(&ours) {
            return Some(stream);
        }
    }

    // Rückfallweg: Wer auch immer sonst zuhört.
    keepassxc_paths().iter().find_map(|p| UnixStream::connect(p).ok())
}

/// Startet die Anwendung im Hintergrund und wartet auf ihren Kanal.
#[cfg(not(windows))]
fn start_app_and_wait(socket: &Path) -> Option<std::os::unix::net::UnixStream> {
    use std::os::unix::net::UnixStream;

    let program = program_path().ok()?;

    // Ohne Argumente — sonst hielte sich die neue Ausgabe selbst für ein
    // Sprachrohr und beide warteten aufeinander.
    std::process::Command::new(program).spawn().ok()?;

    let deadline = std::time::Instant::now() + STARTUP_WAIT;
    while std::time::Instant::now() < deadline {
        if let Ok(stream) = UnixStream::connect(socket) {
            return Some(stream);
        }
        std::thread::sleep(std::time::Duration::from_millis(150));
    }
    None
}

/// Schaufelt Nachrichten in beide Richtungen, bis eine Seite geht.
///
/// Zum Browser hin gilt das Native-Messaging-Format: vier Bytes Länge,
/// kleinstwertiges zuerst, dann die JSON-Nachricht. Auf dem Socket liegt
/// dieselbe Nachricht **ohne** Längenangabe — so macht es KeePassXC auch,
/// und damit spräche deren Sprachrohr notfalls auch mit uns.
#[cfg(not(windows))]
fn pump(stream: std::os::unix::net::UnixStream) {
    use std::io::{Read, Write};

    let Ok(mut to_socket) = stream.try_clone() else { return };

    // Rückweg in einem eigenen Faden: Antworten kommen nicht unbedingt in
    // der Reihenfolge der Anfragen, und manche kommen von selbst.
    let back = std::thread::spawn(move || {
        let mut from_socket = stream;
        let mut buffer = [0u8; 64 * 1024];
        let mut out = std::io::stdout();
        let mut stream_buffer = super::JsonStream::new();

        while let Ok(read) = from_socket.read(&mut buffer) {
            if read == 0 {
                break;
            }

            // Genau eine Nachricht je Browser-Nachricht. Eine `read()`-Portion
            // kann zwei enthalten oder eine halbe — beides würde der Browser
            // als kaputt zurückweisen.
            for message in stream_buffer.push(&buffer[..read]) {
                let Ok(text) = serde_json::to_vec(&message) else { continue };

                let len = (text.len() as u32).to_le_bytes();
                if out.write_all(&len).is_err() || out.write_all(&text).is_err() {
                    return;
                }
                if out.flush().is_err() {
                    return;
                }
            }
        }
    });

    let mut input = std::io::stdin();
    let mut header = [0u8; 4];

    while input.read_exact(&mut header).is_ok() {
        let len = u32::from_le_bytes(header) as usize;

        // Eine Grenze, damit eine kaputte Längenangabe nicht den Speicher
        // auffrisst. Nachrichten der Erweiterung sind wenige Kilobyte groß.
        if len == 0 || len > 1024 * 1024 {
            break;
        }

        let mut message = vec![0u8; len];
        if input.read_exact(&mut message).is_err() {
            break;
        }
        if to_socket.write_all(&message).is_err() || to_socket.flush().is_err() {
            break;
        }
    }

    // Nur die **Senderichtung** schließen, nicht beide.
    //
    // `Shutdown::Both` würde auch den Rückweg kappen — und zwar sofort,
    // während die Antworten noch unterwegs sind. Der Browser bekäme dann
    // nichts oder nur ein Bruchstück zu sehen.
    //
    // So dagegen: Die Gegenstelle merkt am Dateiende, dass nichts mehr
    // kommt, beantwortet fertig, was noch offen ist, und schließt ihrerseits.
    // Erst dann läuft der Rückweg aus.
    let _ = to_socket.shutdown(std::net::Shutdown::Write);
    let _ = back.join();
}

#[cfg(windows)]
fn connect_anywhere() -> Option<()> {
    // Benannte Pipes brauchen eine eigene Anbindung; noch nicht gebaut.
    None
}

#[cfg(windows)]
fn pump(_stream: ()) {}

/// Zeigt das Manifest an dieser Stelle auf unser eigenes Programm?
///
/// Das ist der Unterschied zwischen „eingerichtet" und „hier ist ein fremdes
/// Manifest". Verglichen wird der Pfad, nicht bloß die Existenz der Datei —
/// sonst gälte KeePassXCs Eintrag als unserer.
pub fn points_at(file: &Path, program: &Path) -> bool {
    let Some(manifest) = read(file) else { return false };

    manifest
        .get("path")
        .and_then(Value::as_str)
        .is_some_and(|p| Path::new(p) == program)
}
