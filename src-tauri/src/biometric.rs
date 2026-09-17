//! Der Nachweis, dass der Gerätebesitzer davorsitzt.
//!
//! # Was das ist und was nicht
//!
//! Das hier ist **Authentifizierung**, nicht Schlüsselschutz. Ein
//! Fingerabdruck ist nie Schlüsselmaterial — zwei Scans desselben Fingers
//! ergeben nie dieselben Bits, der Abgleich ist statistisch. Was überall
//! passiert, ist stattdessen:
//!
//! ```text
//! Finger → Vergleich → „ja" → ein gespeicherter Schlüssel wird freigegeben
//! ```
//!
//! Entscheidend ist, **wer** diese Entscheidung durchsetzt:
//!
//! ```text
//! macOS      Secure Enclave — der Chip rückt ohne Finger nichts heraus
//! Windows    TPM über Windows Hello — dasselbe Prinzip
//! Android    Keystore mit setUserAuthenticationRequired
//! Linux      fprintd sagt über D-Bus nur wahr oder falsch. Die Entscheidung
//!            fällt in diesem Prozess — sie hilft gegen die Person am offenen
//!            Rechner, nicht gegen jemanden mit der Datei.
//! ```
//!
//! Deshalb ist der Finger-Weg unter Linux bewusst schwächer eingestuft als
//! die PIN, und `seal.rs` schaltet ihn nur frei, wenn ein Schlüsselbund den
//! eigentlichen Schutz übernimmt.

use zeroize::Zeroizing;

/// Kann diese Plattform eine biometrische Prüfung durchführen?
pub fn available() -> bool {
    imp::available()
}

/// Verlangt den Nachweis. `Ok(())` heißt: bestätigt.
pub fn verify(reason: &str) -> Result<(), String> {
    imp::verify(reason)
}

/* =========================================================
   Gerätegebundener Schlüssel
   ---------------------------------------------------------
   Wo die Plattform einen Schlüssel erst **nach** der Prüfung herausgibt,
   ist die Biometrie selbst der Schutz — dann braucht es weder PIN noch
   Schlüsselbund, und sie darf das Master-Passwort beim Öffnen ersetzen.

   Bisher nur Windows Hello. macOS könnte dasselbe über einen Keychain-
   Eintrag mit `SecAccessControl` (`biometryCurrentSet`); das ist hier noch
   nicht gebaut, dort bleibt Touch ID ein Ja/Nein.
   ========================================================= */

/// Kann diese Plattform einen an die Biometrie gebundenen Schlüssel liefern?
pub fn device_key_available() -> bool {
    imp::device_key_available()
}

/// Wie der Weg auf dieser Plattform heißt — für die Beschriftung der Knöpfe.
pub fn device_key_label() -> Option<&'static str> {
    imp::DEVICE_KEY_LABEL
}

/// Verlangt die Prüfung und leitet daraus 32 Byte Schlüssel ab.
///
/// Dieselbe `challenge` ergibt auf demselben Gerät immer denselben
/// Schlüssel. Ohne Prüfung gibt es keinen — das erzwingt die Hardware,
/// nicht dieses Programm.
pub fn device_key(challenge: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
    imp::device_key(challenge)
}

#[allow(dead_code)] // unter Windows ungenutzt, dort meldet Hello eigene Texte
pub const UNAVAILABLE: &str =
    "Biometrisches Entsperren ist auf dieser Plattform nicht eingerichtet.";

/* =========================================================
   Linux — fprintd über D-Bus
   ========================================================= */

#[cfg(all(unix, not(any(target_os = "macos", target_os = "ios", target_os = "android"))))]
mod imp {
    use std::time::Duration;

    use zbus::blocking::Connection;

    /// Der Anmeldename, unter dem fprintd die Abdrücke führt.
    fn user() -> String {
        std::env::var("USER").unwrap_or_default()
    }

    #[zbus::proxy(
        interface = "net.reactivated.Fprint.Manager",
        default_service = "net.reactivated.Fprint",
        default_path = "/net/reactivated/Fprint/Manager"
    )]
    trait Manager {
        fn get_default_device(&self) -> zbus::Result<zbus::zvariant::OwnedObjectPath>;
    }

    #[zbus::proxy(
        interface = "net.reactivated.Fprint.Device",
        default_service = "net.reactivated.Fprint"
    )]
    trait Device {
        fn list_enrolled_fingers(&self, username: &str) -> zbus::Result<Vec<String>>;
        fn claim(&self, username: &str) -> zbus::Result<()>;
        fn release(&self) -> zbus::Result<()>;
        fn verify_start(&self, finger_name: &str) -> zbus::Result<()>;
        fn verify_stop(&self) -> zbus::Result<()>;

        #[zbus(signal)]
        fn verify_status(&self, result: String, done: bool) -> zbus::Result<()>;
    }

    /// Gerät suchen und prüfen, ob überhaupt ein Finger eingelernt ist.
    ///
    /// Ohne eingelernten Abdruck wäre ein Knopf „mit Fingerabdruck
    /// entsperren" eine Sackgasse — deshalb zählt hier beides.
    fn device() -> Result<DeviceProxyBlocking<'static>, String> {
        let connection =
            Connection::system().map_err(|e| format!("Kein Systembus erreichbar: {e}"))?;

        let manager = ManagerProxyBlocking::new(&connection)
            .map_err(|_| "fprintd antwortet nicht.".to_string())?;

        let path = manager
            .get_default_device()
            .map_err(|_| "Kein Fingerabdruckleser gefunden.".to_string())?;

        DeviceProxyBlocking::builder(&connection)
            .path(path)
            .map_err(|e| format!("Gerätepfad ungültig: {e}"))?
            .build()
            .map_err(|e| format!("Gerät nicht ansprechbar: {e}"))
    }

    pub fn available() -> bool {
        device()
            .and_then(|d| {
                d.list_enrolled_fingers(&user())
                    .map_err(|e| e.to_string())
            })
            .map(|fingers| !fingers.is_empty())
            .unwrap_or(false)
    }

    pub fn verify(_reason: &str) -> Result<(), String> {
        let device = device()?;
        let user = user();

        device
            .claim(&user)
            .map_err(|e| format!("Leser ist belegt: {e}"))?;

        let result = verify_once(&device);

        // Freigeben, auch wenn es schiefging — sonst bleibt der Leser besetzt.
        let _ = device.verify_stop();
        let _ = device.release();

        result
    }

    fn verify_once(device: &DeviceProxyBlocking<'_>) -> Result<(), String> {
        // Erst zuhören, dann starten — sonst geht das Signal verloren.
        let mut stream = device
            .receive_verify_status()
            .map_err(|e| format!("Keine Rückmeldung vom Leser: {e}"))?;

        device
            .verify_start("any")
            .map_err(|e| format!("Prüfung nicht gestartet: {e}"))?;

        // fprintd meldet mehrfach; erst `done` zählt. Der Deckel verhindert,
        // dass die Oberfläche ewig wartet, falls gar nichts kommt.
        let deadline = std::time::Instant::now() + Duration::from_secs(30);

        for signal in stream.by_ref() {
            let args = signal
                .args()
                .map_err(|e| format!("Rückmeldung unlesbar: {e}"))?;

            if args.done {
                return match args.result.as_str() {
                    "verify-match" => Ok(()),
                    "verify-no-match" => Err("Fingerabdruck nicht erkannt.".into()),
                    other => Err(format!("Prüfung fehlgeschlagen: {other}")),
                };
            }

            if std::time::Instant::now() > deadline {
                return Err("Zeitüberschreitung beim Fingerabdruck.".into());
            }
        }

        Err("Die Prüfung wurde abgebrochen.".into())
    }

    pub const DEVICE_KEY_LABEL: Option<&'static str> = None;

    pub fn device_key_available() -> bool {
        false
    }

    pub fn device_key(_challenge: &[u8]) -> Result<zeroize::Zeroizing<[u8; 32]>, String> {
        Err(super::UNAVAILABLE.into())
    }
}

/* =========================================================
   macOS — LocalAuthentication über die Secure Enclave
   ========================================================= */

#[cfg(target_os = "macos")]
mod imp {
    use std::sync::mpsc;

    use objc2::rc::Retained;
    use objc2_foundation::NSString;
    use objc2_local_authentication::{LAContext, LAPolicy};

    /// `LAPolicyDeviceOwnerAuthenticationWithBiometrics` — nur Touch ID,
    /// ohne Rückfall auf das Anmeldepasswort. Der Rückfall ist bei uns die
    /// PIN bzw. das Master-Passwort, und das entscheidet die Oberfläche.
    const POLICY: LAPolicy = LAPolicy(1);

    fn context() -> Retained<LAContext> {
        unsafe { LAContext::new() }
    }

    pub fn available() -> bool {
        unsafe { context().canEvaluatePolicy_error(POLICY).is_ok() }
    }

    pub fn verify(reason: &str) -> Result<(), String> {
        let ctx = context();

        unsafe { ctx.canEvaluatePolicy_error(POLICY) }
            .map_err(|e| format!("Touch ID nicht verfügbar: {e}"))?;

        // `evaluatePolicy` meldet sich über einen Block zurück. Wir warten
        // hier ab — der Aufrufer läuft ohnehin schon außerhalb des
        // Hauptfadens (siehe database.rs).
        let (tx, rx) = mpsc::channel::<bool>();

        let handler = block2::RcBlock::new(move |granted: objc2::runtime::Bool, _err: *mut objc2_foundation::NSError| {
            let _ = tx.send(granted.as_bool());
        });

        unsafe {
            ctx.evaluatePolicy_localizedReason_reply(POLICY, &NSString::from_str(reason), &handler);
        }

        match rx.recv_timeout(std::time::Duration::from_secs(60)) {
            Ok(true) => Ok(()),
            Ok(false) => Err("Touch ID nicht bestätigt.".into()),
            Err(_) => Err("Zeitüberschreitung bei Touch ID.".into()),
        }
    }

    pub const DEVICE_KEY_LABEL: Option<&'static str> = None;

    pub fn device_key_available() -> bool {
        false
    }

    pub fn device_key(_challenge: &[u8]) -> Result<zeroize::Zeroizing<[u8; 32]>, String> {
        Err(super::UNAVAILABLE.into())
    }
}

/* =========================================================
   Android und iOS — über das Tauri-Plugin
   ========================================================= */

#[cfg(any(target_os = "android", target_os = "ios"))]
mod imp {
    // Das Plugin arbeitet mit einem AppHandle; den reicht `database.rs`
    // noch nicht durch. Bis dahin: nicht verfügbar melden, damit die
    // Oberfläche sauber auf PIN und Master-Passwort zurückfällt.
    pub fn available() -> bool {
        false
    }

    pub fn verify(_reason: &str) -> Result<(), String> {
        Err(super::UNAVAILABLE.into())
    }

    pub const DEVICE_KEY_LABEL: Option<&'static str> = None;

    pub fn device_key_available() -> bool {
        false
    }

    pub fn device_key(_challenge: &[u8]) -> Result<zeroize::Zeroizing<[u8; 32]>, String> {
        Err(super::UNAVAILABLE.into())
    }
}

/* =========================================================
   Windows — Windows Hello
   ---------------------------------------------------------
   Zwei Wege, weil es zwei Fragen sind:

   verify       „Bist du es?" über UserConsentVerifier. Ein Ja/Nein, für
                das Bestätigen beim Anzeigen eines Passworts.

   device_key   Ein RSA-Schlüssel im TPM, angelegt über KeyCredentialManager.
                Er signiert nur nach erfolgreicher Prüfung. Die Signatur über
                einen festen Zufallswert ist bei PKCS#1 v1.5 immer dieselbe —
                aus ihr wird der Schlüssel für das Siegel. KeePassXC macht es
                genauso.
   ========================================================= */

#[cfg(windows)]
mod imp {
    use sha2::{Digest, Sha256};
    use windows::core::{factory, w, Array, HSTRING, PCWSTR};
    use windows::Security::Credentials::UI::{
        UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
    };
    use windows::Security::Credentials::{
        KeyCredential, KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
    };
    use windows::Security::Cryptography::CryptographicBuffer;
    use windows::Win32::System::WinRT::IUserConsentVerifierInterop;
    use windows::Win32::UI::WindowsAndMessaging::{FindWindowW, GetForegroundWindow, SetForegroundWindow};
    use windows_future::IAsyncOperation;
    use zeroize::Zeroizing;

    pub const DEVICE_KEY_LABEL: Option<&'static str> = Some("Windows Hello");

    /// Name des Schlüssels im TPM. Er gehört diesem Benutzerkonto und
    /// diesem Gerät — auf einem anderen Rechner gibt es ihn nicht.
    const CREDENTIAL: &str = "de.wuefl.wkeepass";

    /// Trennt die Ableitung von jeder anderen Verwendung der Signatur.
    const KEY_INFO: &[u8] = b"wkeepass-windows-hello-v1";

    pub fn available() -> bool {
        UserConsentVerifier::CheckAvailabilityAsync()
            .and_then(|op| op.get())
            .map(|a| a == UserConsentVerifierAvailability::Available)
            .unwrap_or(false)
    }

    pub fn verify(reason: &str) -> Result<(), String> {
        // Über die Interop-Schnittstelle mit Fensterbezug: Ohne ihn geht die
        // Abfrage einer Desktop-Anwendung gern hinter dem Fenster auf.
        let interop = factory::<UserConsentVerifier, IUserConsentVerifierInterop>()
            .map_err(|e| format!("Windows Hello nicht erreichbar: {e}"))?;

        let window = unsafe { GetForegroundWindow() };
        let op: IAsyncOperation<UserConsentVerificationResult> = unsafe {
            interop.RequestVerificationForWindowAsync(window, &HSTRING::from(reason))
        }
        .map_err(|e| format!("Windows Hello nicht gestartet: {e}"))?;

        match op.get().map_err(|e| format!("Windows Hello abgebrochen: {e}"))? {
            UserConsentVerificationResult::Verified => Ok(()),
            UserConsentVerificationResult::Canceled => Err("Windows Hello abgebrochen.".into()),
            UserConsentVerificationResult::RetriesExhausted => {
                Err("Zu viele Fehlversuche bei Windows Hello.".into())
            }
            other => Err(format!("Windows Hello hat nicht bestätigt (Code {}).", other.0)),
        }
    }

    pub fn device_key_available() -> bool {
        KeyCredentialManager::IsSupportedAsync()
            .and_then(|op| op.get())
            .unwrap_or(false)
    }

    pub fn device_key(challenge: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
        let credential = open_or_create()?;

        bring_prompt_to_front();
        let data = CryptographicBuffer::CreateFromByteArray(challenge)
            .map_err(|e| format!("Puffer nicht anlegbar: {e}"))?;
        let signed = credential
            .RequestSignAsync(&data)
            .and_then(|op| op.get())
            .map_err(|e| format!("Windows Hello abgebrochen: {e}"))?;

        check(signed.Status().map_err(|e| e.to_string())?)?;

        let buffer = signed.Result().map_err(|e| format!("Keine Signatur: {e}"))?;
        let mut signature = Array::<u8>::new();
        CryptographicBuffer::CopyToByteArray(&buffer, &mut signature)
            .map_err(|e| format!("Signatur nicht lesbar: {e}"))?;

        if signature.is_empty() {
            return Err("Windows Hello hat eine leere Signatur geliefert.".into());
        }

        let mut hasher = Sha256::new();
        hasher.update(KEY_INFO);
        hasher.update(&signature[..]);
        Ok(Zeroizing::new(hasher.finalize().into()))
    }

    /// Holt den Schlüssel aus dem TPM oder legt ihn beim ersten Mal an.
    ///
    /// Das Anlegen verlangt selbst eine Prüfung — beim Einrichten fragt
    /// Windows deshalb zweimal nach.
    fn open_or_create() -> Result<KeyCredential, String> {
        let name = HSTRING::from(CREDENTIAL);

        let opened = KeyCredentialManager::OpenAsync(&name)
            .and_then(|op| op.get())
            .map_err(|e| format!("Windows Hello nicht erreichbar: {e}"))?;

        match opened.Status().map_err(|e| e.to_string())? {
            KeyCredentialStatus::Success => {
                opened.Credential().map_err(|e| format!("Schlüssel nicht lesbar: {e}"))
            }
            KeyCredentialStatus::NotFound => {
                bring_prompt_to_front();
                let created = KeyCredentialManager::RequestCreateAsync(
                    &name,
                    KeyCredentialCreationOption::FailIfExists,
                )
                .and_then(|op| op.get())
                .map_err(|e| format!("Windows Hello abgebrochen: {e}"))?;

                check(created.Status().map_err(|e| e.to_string())?)?;
                created.Credential().map_err(|e| format!("Schlüssel nicht lesbar: {e}"))
            }
            other => check(other).and(Err("Windows Hello nicht verfügbar.".into())),
        }
    }

    fn check(status: KeyCredentialStatus) -> Result<(), String> {
        match status {
            KeyCredentialStatus::Success => Ok(()),
            KeyCredentialStatus::UserCanceled => Err("Windows Hello abgebrochen.".into()),
            KeyCredentialStatus::UserPrefersPassword => {
                Err("Windows Hello abgelehnt — bitte mit dem Master-Passwort öffnen.".into())
            }
            KeyCredentialStatus::SecurityDeviceLocked => {
                Err("Das TPM ist nach zu vielen Fehlversuchen gesperrt.".into())
            }
            KeyCredentialStatus::NotFound => {
                Err("Der Windows-Hello-Schlüssel fehlt — bitte neu einrichten.".into())
            }
            other => Err(format!("Windows Hello meldet einen Fehler (Code {}).", other.0)),
        }
    }

    /// Holt das Hello-Fenster nach vorn.
    ///
    /// `KeyCredentialManager` kennt anders als `UserConsentVerifier` keinen
    /// Fensterbezug, und die Abfrage geht bei Desktop-Anwendungen oft hinter
    /// dem eigenen Fenster auf. Ein kurzer Wächter sucht sie und stellt sie
    /// nach vorn — derselbe Umweg, den KeePassXC nimmt.
    fn bring_prompt_to_front() {
        std::thread::spawn(|| {
            for _ in 0..50 {
                std::thread::sleep(std::time::Duration::from_millis(100));
                if let Ok(window) = unsafe { FindWindowW(w!("Credential Dialog Xaml Host"), PCWSTR::null()) } {
                    if !window.is_invalid() {
                        let _ = unsafe { SetForegroundWindow(window) };
                        return;
                    }
                }
            }
        });
    }
}
