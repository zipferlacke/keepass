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
//!
//! # Windows
//!
//! Dort schlägt der Browser nicht in einem Ordner nach, sondern in der
//! Registry: Unter `HKCU\Software\<Browser>\NativeMessagingHosts\<Name>`
//! steht der Pfad zur Manifest-Datei. Die Datei legen wir unter
//! `%LOCALAPPDATA%\WKeePass` ab. Zeigte der Eintrag vorher auf KeePassXC,
//! merken wir uns das im selben Schlüssel und stellen es beim Abschalten
//! wieder her.

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
    /// Verzeichnisse, von denen eines existiert, wenn der Browser schon
    /// einmal gelaufen ist.
    probe: Vec<PathBuf>,
    /// Windows: der Registry-Schlüssel unter HKCU, in dem er nachschlägt.
    #[cfg(windows)]
    registry: &'static str,
}

impl Target {
    pub fn file(&self) -> PathBuf {
        self.dir.join(format!("{HOST_NAME}.json"))
    }

    pub fn installed(&self) -> bool {
        // Ein Verzeichnis des Browsers ist der Beleg: Es existiert nur, wenn
        // er schon einmal gelaufen ist. Wir legen es nicht selbst an —
        // sonst schriebe man Manifeste für Browser, die es nicht gibt.
        self.probe.iter().any(|p| p.is_dir())
    }

    /// Findet der Browser über diesen Weg unser Programm?
    pub fn is_ours(&self, program: &Path) -> bool {
        #[cfg(windows)]
        if reg::current(self.registry).as_deref() != Some(self.file().as_path()) {
            return false;
        }
        points_at(&self.file(), program)
    }

    /// Das Manifest, das bisher galt — die beste Vorlage für unseres.
    fn previous(&self) -> Option<Value> {
        #[cfg(windows)]
        if let Some(path) = reg::current(self.registry).filter(|p| *p != self.file()) {
            return read(&path);
        }
        read(&self.file())
    }
}

/// Alle Browser, die auf diesem Rechner in Frage kommen.
///
/// Zurück kommt jeder bekannte Ort; ob er tatsächlich gilt, sagt
/// `Target::installed`.
#[cfg(not(windows))]
pub fn targets() -> Vec<Target> {
    let Some(home) = home_dir() else { return Vec::new() };
    let mut out = Vec::new();

    let target = |name, flavour, dir: PathBuf| Target {
        name,
        flavour,
        probe: dir.parent().map(Path::to_path_buf).into_iter().collect(),
        dir,
    };

    for (name, flavour, relative) in LOCATIONS {
        out.push(target(name, *flavour, home.join(relative)));
    }

    // Flatpak spiegelt dieselben Pfade unter ~/.var/app/<Kennung>/ —
    // dieselbe Erweiterung, anderer Ablageort.
    for (name, flavour, id, relative) in FLATPAK_LOCATIONS {
        out.push(target(name, *flavour, home.join(".var/app").join(id).join(relative)));
    }

    out
}

/// Windows: ein Registry-Schlüssel je Browserfamilie.
///
/// Brave, Vivaldi und Opera lesen den Schlüssel von Chrome mit — genauso
/// trägt sich KeePassXC ein. Die Prüfordner liegen unter `%LOCALAPPDATA%`
/// bzw. `%APPDATA%` (Firefox).
#[cfg(windows)]
pub fn targets() -> Vec<Target> {
    let env = |name| std::env::var_os(name).map(PathBuf::from);
    let (Some(local), Some(roaming)) = (env("LOCALAPPDATA"), env("APPDATA")) else { return Vec::new() };
    let base = local.join("WKeePass").join("NativeMessagingHosts");

    let list: [(&str, Flavour, &str, &str, Vec<PathBuf>); 4] = [
        ("Firefox", Flavour::Firefox, "firefox", r"Software\Mozilla\NativeMessagingHosts",
            vec![roaming.join(r"Mozilla\Firefox"), roaming.join("librewolf"), roaming.join(r"Waterfox")]),
        ("Chrome / Brave / Vivaldi", Flavour::Chromium, "chrome", r"Software\Google\Chrome\NativeMessagingHosts",
            vec![local.join(r"Google\Chrome"), local.join(r"BraveSoftware\Brave-Browser"), local.join("Vivaldi"),
                 roaming.join(r"Opera Software")]),
        ("Chromium", Flavour::Chromium, "chromium", r"Software\Chromium\NativeMessagingHosts",
            vec![local.join("Chromium")]),
        ("Edge", Flavour::Chromium, "edge", r"Software\Microsoft\Edge\NativeMessagingHosts",
            vec![local.join(r"Microsoft\Edge")]),
    ];

    list.into_iter()
        .map(|(name, flavour, slug, registry, probe)| Target { name, flavour, dir: base.join(slug), probe, registry })
        .collect()
}

/// Ablageorte im Heimatverzeichnis. Linux und macOS trennen sich hier, weil
/// die Browser dort andere Verzeichnisnamen benutzen.
#[cfg(not(any(target_os = "macos", windows)))]
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

#[cfg(not(any(target_os = "macos", windows)))]
const FLATPAK_LOCATIONS: &[(&str, Flavour, &str, &str)] = &[
    ("Firefox (Flatpak)", Flavour::Firefox, "org.mozilla.firefox", ".mozilla/native-messaging-hosts"),
    ("Chrome (Flatpak)", Flavour::Chromium, "com.google.Chrome", "config/google-chrome/NativeMessagingHosts"),
    ("Chromium (Flatpak)", Flavour::Chromium, "org.chromium.Chromium", "config/chromium/NativeMessagingHosts"),
    ("Brave (Flatpak)", Flavour::Chromium, "com.brave.Browser", "config/BraveSoftware/Brave-Browser/NativeMessagingHosts"),
    ("Vivaldi (Flatpak)", Flavour::Chromium, "com.vivaldi.Vivaldi", "config/vivaldi/NativeMessagingHosts"),
];

#[cfg(target_os = "macos")]
const FLATPAK_LOCATIONS: &[(&str, Flavour, &str, &str)] = &[];

#[cfg(not(windows))]
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
        let vorlage = target.previous();
        let manifest = build(target.flavour, program, vorlage.as_ref());

        let result = std::fs::create_dir_all(&target.dir).and_then(|()| {
            std::fs::write(&file, serde_json::to_string_pretty(&manifest).unwrap_or_default())
        });
        #[cfg(windows)]
        let result = result.and_then(|()| reg::set(target.registry, &file));

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
        if !file.is_file() || !target.is_ours(program) {
            continue;
        }

        // Windows: erst den Registry-Eintrag zurück auf den Vorgänger.
        #[cfg(windows)]
        let result = reg::reset(target.registry).and_then(|()| std::fs::remove_file(&file));
        #[cfg(not(windows))]
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

/// Wo unsere eigene ausführbare Datei liegt — so, wie der Browser sie
/// starten kann.
pub fn program_path() -> Result<PathBuf, String> {
    #[cfg(target_os = "linux")]
    if let Some(launcher) = flatpak_launcher() {
        return Ok(launcher);
    }
    // Ein AppImage läuft aus einem Einhängepunkt unter /tmp, der bei jedem
    // Start anders heißt — gemeint ist die .AppImage-Datei selbst.
    #[cfg(target_os = "linux")]
    if let Some(image) = std::env::var_os("APPIMAGE").filter(|p| !p.is_empty()) {
        return Ok(PathBuf::from(image));
    }
    std::env::current_exe().map_err(|e| format!("Eigener Pfad nicht ermittelbar: {e}"))
}

/// Im Flatpak ist `current_exe()` `/app/bin/wkeepass` — ein Pfad, den es
/// nur in der Sandbox gibt. Der Browser draußen startet stattdessen den
/// Starter, den Flatpak unter `exports/bin/<Kennung>` ablegt; der ruft
/// `flatpak run` und reicht die Argumente durch.
///
/// Wo die Installation liegt (System: `/var/lib/flatpak`, Benutzer:
/// `~/.local/share/flatpak`), verrät `/.flatpak-info` über `app-path`.
#[cfg(target_os = "linux")]
fn flatpak_launcher() -> Option<PathBuf> {
    let id = std::env::var("FLATPAK_ID").ok()?;
    let info = std::fs::read_to_string("/.flatpak-info").ok()?;
    launcher_from_info(&id, &info)
}

#[cfg(target_os = "linux")]
fn launcher_from_info(id: &str, info: &str) -> Option<PathBuf> {
    let app_path = info.lines().find_map(|l| l.trim().strip_prefix("app-path="))?;
    let (root, _) = app_path.split_once(&format!("/app/{id}/"))?;
    Some(PathBuf::from(root).join("exports/bin").join(id))
}

/// Windows: der Registry-Eintrag, über den ein Browser das Manifest findet.
#[cfg(windows)]
mod reg {
    use std::path::{Path, PathBuf};

    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
    use winreg::RegKey;

    /// Worauf der Eintrag vor uns zeigte — meist KeePassXC.
    const VORHER: &str = "WKeePassVorher";

    fn path(base: &str) -> String {
        format!(r"{base}\{}", super::HOST_NAME)
    }

    /// Die Manifest-Datei, auf die der Eintrag gerade zeigt.
    pub fn current(base: &str) -> Option<PathBuf> {
        RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey(path(base))
            .ok()?
            .get_value::<String, _>("")
            .ok()
            .map(PathBuf::from)
    }

    /// Lässt den Eintrag auf `file` zeigen und merkt sich den Vorgänger.
    pub fn set(base: &str, file: &Path) -> std::io::Result<()> {
        let (key, _) = RegKey::predef(HKEY_CURRENT_USER).create_subkey(path(base))?;
        if let Ok(before) = key.get_value::<String, _>("") {
            if Path::new(&before) != file {
                key.set_value(VORHER, &before)?;
            }
        }
        key.set_value("", &file.to_string_lossy().to_string())
    }

    /// Stellt den Vorgänger wieder her — oder entfernt den Eintrag, wenn
    /// es keinen gab.
    pub fn reset(base: &str) -> std::io::Result<()> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let key = hkcu.open_subkey_with_flags(path(base), KEY_READ | KEY_WRITE)?;
        match key.get_value::<String, _>(VORHER) {
            Ok(before) => {
                key.set_value("", &before)?;
                key.delete_value(VORHER)
            }
            Err(_) => {
                drop(key);
                hkcu.delete_subkey(path(base))
            }
        }
    }
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
    // Der Namensraum der Pipes gilt für den ganzen Rechner. Mit dem
    // Benutzernamen darin kommen sich zwei angemeldete Konten nicht in die
    // Quere — so hält es KeePassXC auch.
    #[cfg(windows)]
    {
        let user = std::env::var("USERNAME").unwrap_or_default();
        return PathBuf::from(format!(r"\\.\pipe\{CHANNEL}.{user}"));
    }

    #[cfg(not(windows))]
    {
        if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
            // Im Flatpak bekommt jede gestartete Instanz ein eigenes, leeres
            // XDG_RUNTIME_DIR. Gemeinsam ist nur app/<Kennung>/ — dort
            // treffen sich die App und der vom Browser gestartete Teil.
            #[cfg(target_os = "linux")]
            if let Ok(id) = std::env::var("FLATPAK_ID") {
                return PathBuf::from(dir).join("app").join(id).join(CHANNEL);
            }
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

    #[cfg(target_os = "linux")]
    #[test]
    fn flatpak_starter_aus_der_installation() {
        let system = "[Application]\nname=de.wuefl.wkeepass\n\n[Instance]\n\
            app-path=/var/lib/flatpak/app/de.wuefl.wkeepass/x86_64/master/abc123/files\n";
        assert_eq!(
            launcher_from_info("de.wuefl.wkeepass", system),
            Some(PathBuf::from("/var/lib/flatpak/exports/bin/de.wuefl.wkeepass"))
        );

        let user = "[Instance]\n\
            app-path=/home/anna/.local/share/flatpak/app/de.wuefl.wkeepass/aarch64/master/f00/files\n";
        assert_eq!(
            launcher_from_info("de.wuefl.wkeepass", user),
            Some(PathBuf::from("/home/anna/.local/share/flatpak/exports/bin/de.wuefl.wkeepass"))
        );

        assert_eq!(launcher_from_info("de.wuefl.wkeepass", "[Instance]\n"), None);
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
#[cfg(not(windows))]
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
    // Sprachrohr und beide warteten aufeinander. Und ohne die Leitungen des
    // Browsers: Erbte das Fenster stdin/stdout, hinge der Browser an einem
    // Programm, das nie mit ihm spricht.
    std::process::Command::new(program)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;

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

/* ---------------------------------------------------------
   Das Sprachrohr unter Windows — dieselben drei Schritte, über eine
   benannte Pipe. tokio, weil auf einer Pipe nur überlappend gleichzeitig
   gelesen und geschrieben werden kann (siehe api.rs).
   --------------------------------------------------------- */

#[cfg(windows)]
pub fn run_proxy() {
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread().enable_all().build() else {
        return;
    };
    runtime.block_on(async {
        match connect_anywhere().await {
            Some(pipe) => pump(pipe).await,
            None => eprintln!("WKeePass: keine Gegenstelle erreichbar"),
        }
    });
}

/// Öffnet eine Pipe. „Belegt" heißt: Alle Instanzen sind gerade verbunden,
/// gleich wird eine frei — kurz warten und nochmal.
#[cfg(windows)]
async fn open_pipe(path: &Path) -> Option<tokio::net::windows::named_pipe::NamedPipeClient> {
    const ERROR_PIPE_BUSY: i32 = 231;
    for _ in 0..40 {
        match tokio::net::windows::named_pipe::ClientOptions::new().open(path) {
            Ok(client) => return Some(client),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            Err(_) => return None,
        }
    }
    None
}

#[cfg(windows)]
async fn connect_anywhere() -> Option<tokio::net::windows::named_pipe::NamedPipeClient> {
    let ours = socket_path();
    if let Some(pipe) = open_pipe(&ours).await {
        return Some(pipe);
    }

    // Wie unter Unix: nur die gebaute Fassung startet sich selbst.
    if !cfg!(debug_assertions) && spawn_app().is_some() {
        let deadline = std::time::Instant::now() + STARTUP_WAIT;
        while std::time::Instant::now() < deadline {
            if let Some(pipe) = open_pipe(&ours).await {
                return Some(pipe);
            }
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        }
    }

    for path in keepassxc_paths() {
        if let Some(pipe) = open_pipe(&path).await {
            return Some(pipe);
        }
    }
    None
}

/// Startet das Fenster, losgelöst vom Browser.
///
/// Chrome legt seine Native-Messaging-Programme in ein Job-Objekt und
/// beendet beim Trennen alles darin — auch ein Fenster, das wir daraus
/// gestartet hätten. `CREATE_BREAKAWAY_FROM_JOB` löst es davon; erlaubt der
/// Job das nicht, eben ohne.
#[cfg(windows)]
fn spawn_app() -> Option<()> {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};

    const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

    let program = program_path().ok()?;
    let start = |flags: u32| {
        Command::new(&program)
            .creation_flags(flags)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
    };
    start(CREATE_BREAKAWAY_FROM_JOB | CREATE_NEW_PROCESS_GROUP)
        .or_else(|_| start(CREATE_NEW_PROCESS_GROUP))
        .ok()
        .map(|_| ())
}

/// Wie `pump` für Unix — Längenangabe zum Browser, nacktes JSON zur Pipe.
#[cfg(windows)]
async fn pump(pipe: tokio::net::windows::named_pipe::NamedPipeClient) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut from_pipe, mut to_pipe) = tokio::io::split(pipe);

    let back = tokio::spawn(async move {
        let mut buffer = vec![0u8; 64 * 1024];
        let mut out = tokio::io::stdout();
        let mut stream_buffer = super::JsonStream::new();

        loop {
            let read = match from_pipe.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            for message in stream_buffer.push(&buffer[..read]) {
                let Ok(text) = serde_json::to_vec(&message) else { continue };
                let len = (text.len() as u32).to_le_bytes();
                if out.write_all(&len).await.is_err()
                    || out.write_all(&text).await.is_err()
                    || out.flush().await.is_err()
                {
                    return;
                }
            }
        }
    });

    let mut input = tokio::io::stdin();
    let mut header = [0u8; 4];

    while input.read_exact(&mut header).await.is_ok() {
        let len = u32::from_le_bytes(header) as usize;
        if len == 0 || len > 1024 * 1024 {
            break;
        }
        let mut message = vec![0u8; len];
        if input.read_exact(&mut message).await.is_err() {
            break;
        }
        if to_pipe.write_all(&message).await.is_err() || to_pipe.flush().await.is_err() {
            break;
        }
    }

    // Eine Pipe kennt kein halbes Schließen wie der Socket. Hat der Browser
    // seine Seite zugemacht, liest ohnehin niemand mehr eine Antwort.
    back.abort();
}

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
