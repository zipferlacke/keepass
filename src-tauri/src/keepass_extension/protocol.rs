//! Die Verschlüsselung zwischen Erweiterung und Kern.
//!
//! `keepassxc-browser` spricht NaCls `crypto_box`: X25519 zum Aushandeln,
//! XSalsa20-Poly1305 zum Verschlüsseln. Genau das, nichts anderes — das
//! `chacha20poly1305`, das wir für das Siegel benutzen, passt hier nicht.
//!
//! # Der Ablauf
//!
//! Die erste Nachricht geht **unverschlüsselt**: Beide Seiten schicken ihren
//! öffentlichen Sitzungsschlüssel (`change-public-keys`). Ab da ist alles
//! verschlüsselt.
//!
//! ```text
//! Erweiterung                          Kern
//!     │  change-public-keys, publicKey  │
//!     ├────────────────────────────────▶│
//!     │        publicKey, success       │
//!     │◀────────────────────────────────┤
//!     │                                 │
//!     │  action, message(verschlüsselt) │
//!     ├────────────────────────────────▶│
//!     │  message(verschlüsselt)         │
//!     │◀────────────────────────────────┤
//! ```
//!
//! # Zwei Paare, nicht verwechseln
//!
//! **Sitzungsschlüssel** entstehen bei jeder Verbindung neu und
//! verschlüsseln den Verkehr. Sie sind nach dem Schließen wertlos.
//!
//! **Verknüpfungsschlüssel** entstehen einmal beim Verknüpfen, liegen
//! dauerhaft in der Datenbank und dienen nur der Wiedererkennung — sie
//! verschlüsseln nichts. Wer beide vermengt, bekommt eine Anbindung, die
//! beim ersten Neustart bricht.
//!
//! # Das Nonce der Antwort
//!
//! Die Antwort benutzt **nicht** das Nonce der Anfrage, sondern das um eins
//! erhöhte. Gezählt wird über alle 24 Bytes, kleinstwertiges Byte zuerst,
//! mit Übertrag — `sodium_increment` aus libsodium. Rechnet man falsch
//! herum, verwirft die Erweiterung die Antwort wortlos, ohne Fehlermeldung.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use crypto_box::{
    aead::{Aead, OsRng},
    PublicKey, SalsaBox, SecretKey,
};

/// Länge eines Nonce in Bytes — durch XSalsa20 vorgegeben.
pub const NONCE_LEN: usize = 24;

pub type Nonce = [u8; NONCE_LEN];

/// Erhöht ein Nonce um eins.
///
/// Kleinstwertiges Byte zuerst, mit Übertrag — so macht es
/// `sodium_increment`, und so erwartet es die Erweiterung. Läuft das ganze
/// Feld über, beginnt es wieder bei null; das ist bei 24 Bytes ohne
/// praktische Bedeutung, aber ohne Sonderfall auch ohne Fehlerquelle.
pub fn increment_nonce(nonce: &Nonce) -> Nonce {
    let mut out = *nonce;
    let mut carry = 1u16;

    for byte in out.iter_mut() {
        carry += u16::from(*byte);
        *byte = carry as u8;
        carry >>= 8;
    }
    out
}

/// Liest ein Nonce aus seiner Base64-Darstellung.
pub fn decode_nonce(text: &str) -> Result<Nonce, String> {
    let bytes = B64.decode(text).map_err(|_| "Nonce ist kein Base64.".to_string())?;
    bytes
        .try_into()
        .map_err(|_| format!("Nonce muss {NONCE_LEN} Bytes lang sein."))
}

pub fn encode(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

pub fn decode(text: &str) -> Result<Vec<u8>, String> {
    B64.decode(text).map_err(|_| "Kein gültiges Base64.".to_string())
}

/// Ein X25519-Schlüsselpaar.
///
/// Dient je nach Verwendung als Sitzungs- oder als Verknüpfungspaar — der
/// Unterschied liegt allein darin, wo es aufbewahrt wird.
pub struct KeyPair {
    secret: SecretKey,
    public: PublicKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        let secret = SecretKey::generate(&mut OsRng);
        let public = secret.public_key();
        Self { secret, public }
    }

    /// Der öffentliche Teil, wie er über die Leitung geht.
    pub fn public_base64(&self) -> String {
        encode(self.public.as_bytes())
    }
}

/// Eine offene, verschlüsselte Sitzung mit einer Erweiterung.
pub struct Session {
    boxed: SalsaBox,
}

impl Session {
    /// Bildet den gemeinsamen Schlüssel aus unserem geheimen und dem
    /// öffentlichen Teil der Gegenstelle.
    pub fn new(ours: &KeyPair, theirs_base64: &str) -> Result<Self, String> {
        let raw = decode(theirs_base64)?;
        let raw: [u8; 32] = raw
            .try_into()
            .map_err(|_| "Öffentlicher Schlüssel muss 32 Bytes lang sein.".to_string())?;

        Ok(Self {
            boxed: SalsaBox::new(&PublicKey::from(raw), &ours.secret),
        })
    }

    /// Entschlüsselt den Inhalt einer Nachricht.
    ///
    /// Schlägt das fehl, ist entweder der Schlüssel falsch oder jemand hat
    /// unterwegs daran gedreht — beides führt zum Abbruch, nicht zu einem
    /// Rateversuch.
    pub fn open(&self, message_base64: &str, nonce: &Nonce) -> Result<Vec<u8>, String> {
        let cipher = decode(message_base64)?;
        self.boxed
            .decrypt(nonce.into(), cipher.as_slice())
            .map_err(|_| "Nachricht ließ sich nicht entschlüsseln.".to_string())
    }

    /// Verschlüsselt eine Antwort.
    pub fn seal(&self, plain: &[u8], nonce: &Nonce) -> Result<String, String> {
        self.boxed
            .encrypt(nonce.into(), plain)
            .map(|cipher| encode(&cipher))
            .map_err(|_| "Antwort ließ sich nicht verschlüsseln.".to_string())
    }

}

#[cfg(test)]
mod tests {
    /// Ein zufälliges Nonce — nur hier gebraucht.
    ///
    /// Im Betrieb gibt die Erweiterung das Nonce immer vor; wir zählen es
    /// für die Antwort nur hoch. Erzeugt wird eines also einzig in den Tests.
    fn fresh_nonce() -> Nonce {
        use rand_core::RngCore;
        let mut nonce = [0u8; NONCE_LEN];
        rand_core::OsRng.fill_bytes(&mut nonce);
        nonce
    }

    use super::*;

    #[test]
    fn nonce_zaehlt_kleinstwertiges_byte_zuerst() {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[0] = 41;

        let next = increment_nonce(&nonce);
        assert_eq!(next[0], 42);
        assert!(next[1..].iter().all(|b| *b == 0), "kein Byte darf mitwandern");
    }

    #[test]
    fn nonce_traegt_ueber() {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[0] = 0xff;

        let next = increment_nonce(&nonce);
        assert_eq!(next[0], 0x00, "das volle Byte läuft über");
        assert_eq!(next[1], 0x01, "der Übertrag landet im nächsten Byte");
    }

    #[test]
    fn nonce_traegt_ueber_mehrere_bytes() {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[0] = 0xff;
        nonce[1] = 0xff;
        nonce[2] = 0x07;

        let next = increment_nonce(&nonce);
        assert_eq!(&next[0..3], &[0x00, 0x00, 0x08]);
    }

    #[test]
    fn nonce_laeuft_am_ende_um() {
        let nonce = [0xffu8; NONCE_LEN];
        assert_eq!(increment_nonce(&nonce), [0u8; NONCE_LEN]);
    }

    /// Beide Seiten müssen aus vertauschten Hälften denselben Schlüssel
    /// bilden — sonst passt nichts zusammen.
    #[test]
    fn beide_seiten_kommen_auf_denselben_schluessel() {
        let kern = KeyPair::generate();
        let browser = KeyPair::generate();

        let a = Session::new(&kern, &browser.public_base64()).unwrap();
        let b = Session::new(&browser, &kern.public_base64()).unwrap();

        let nonce = fresh_nonce();
        let cipher = a.seal(b"{\"action\":\"test\"}", &nonce).unwrap();

        assert_eq!(b.open(&cipher, &nonce).unwrap(), b"{\"action\":\"test\"}");
    }

    /// So läuft es tatsächlich: Die Antwort wird mit dem erhöhten Nonce
    /// verschlüsselt, und die Gegenstelle rechnet dasselbe.
    #[test]
    fn antwort_nutzt_das_erhoehte_nonce() {
        let kern = KeyPair::generate();
        let browser = KeyPair::generate();

        let seite_kern = Session::new(&kern, &browser.public_base64()).unwrap();
        let seite_browser = Session::new(&browser, &kern.public_base64()).unwrap();

        let anfrage_nonce = fresh_nonce();
        let antwort_nonce = increment_nonce(&anfrage_nonce);

        let antwort = seite_kern.seal(b"{\"success\":\"true\"}", &antwort_nonce).unwrap();

        // Mit dem alten Nonce darf es nicht aufgehen …
        assert!(seite_browser.open(&antwort, &anfrage_nonce).is_err());
        // … mit dem erhöhten schon.
        assert_eq!(
            seite_browser.open(&antwort, &antwort_nonce).unwrap(),
            b"{\"success\":\"true\"}"
        );
    }

    #[test]
    fn veraenderte_nachricht_wird_abgelehnt() {
        let kern = KeyPair::generate();
        let browser = KeyPair::generate();

        let a = Session::new(&kern, &browser.public_base64()).unwrap();
        let b = Session::new(&browser, &kern.public_base64()).unwrap();

        let nonce = fresh_nonce();
        let mut cipher = decode(&a.seal(b"geheim", &nonce).unwrap()).unwrap();
        cipher[0] ^= 0x01;

        assert!(b.open(&encode(&cipher), &nonce).is_err());
    }

    #[test]
    fn nonce_falscher_laenge_wird_abgelehnt() {
        assert!(decode_nonce(&encode(&[0u8; 12])).is_err());
        assert!(decode_nonce(&encode(&[0u8; NONCE_LEN])).is_ok());
    }
}
