//! Anbindung an die Browser-Erweiterung `keepassxc-browser`.
//!
//! Zwei Hälften, sauber getrennt:
//!
//!   `route`     wo unser Programm liegt, wo der Kanal liegt, und das
//!               Sprachrohr, das der Browser startet
//!   `api`       was über diesen Kanal gesprochen wird — die Gegenstelle
//!               zu dem, was sonst KeePassXC beantwortet
//!
//! Dazwischen `protocol`: die Verschlüsselung. Sie steht für sich, weil sie
//! ohne Socket und ohne Datenbank prüfbar ist — und weil ein Fehler darin
//! sich sonst als „die Erweiterung tut nichts" tarnen würde.

pub mod api;
pub mod protocol;
pub mod route;

/// Sammelt Bytes und gibt vollständige JSON-Nachrichten heraus.
///
/// # Warum das nötig ist
///
/// Auf dem Kanal liegen die Nachrichten nackt hintereinander, ohne
/// Längenangabe — so macht es KeePassXC. Ein `read()` liefert deshalb, was
/// gerade da ist, und das ist selten genau eine Nachricht:
///
/// ```text
/// {"action":"a",…}{"action":"b",…}     zwei in einer Portion
/// {"action":"a","message":"AbCd        eine halbe Portion
/// ```
///
/// Wer eine Portion einfach weiterreicht, verschmilzt im ersten Fall zwei
/// Nachrichten und zerschneidet im zweiten eine. Der Browser bekommt dann
/// kaputtes JSON oder ein abgeschnittenes Base64-Feld — und meldet
/// „invalid encoding", ohne dass irgendetwas an der Verschlüsselung falsch
/// wäre.
///
/// Deshalb wird gesammelt, bis eine Nachricht vollständig ist, und nur die
/// wird weitergegeben. Der Rest bleibt liegen.
#[derive(Default)]
pub struct JsonStream {
    buffer: Vec<u8>,
}

impl JsonStream {
    pub fn new() -> Self {
        Self::default()
    }

    /// Nimmt neue Bytes auf und liefert jede darin vollständige Nachricht.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<serde_json::Value> {
        self.buffer.extend_from_slice(bytes);

        let mut out = Vec::new();
        let mut consumed = 0;

        loop {
            let rest = &self.buffer[consumed..];
            if rest.iter().all(u8::is_ascii_whitespace) {
                consumed = self.buffer.len();
                break;
            }

            let mut reader = serde_json::Deserializer::from_slice(rest).into_iter::<serde_json::Value>();

            match reader.next() {
                Some(Ok(value)) => {
                    consumed += reader.byte_offset();
                    out.push(value);
                }
                // Unvollständig — der Rest kommt mit dem nächsten `read()`.
                Some(Err(err)) if err.is_eof() => break,
                // Wirklich kaputt: alles verwerfen, sonst blieben wir für
                // immer an derselben Stelle hängen.
                Some(Err(_)) => {
                    consumed = self.buffer.len();
                    break;
                }
                None => break,
            }
        }

        self.buffer.drain(..consumed);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::JsonStream;

    #[test]
    fn zwei_nachrichten_in_einer_portion_bleiben_zwei() {
        let mut stream = JsonStream::new();
        let out = stream.push(br#"{"action":"a"}{"action":"b"}"#);

        assert_eq!(out.len(), 2);
        assert_eq!(out[0]["action"], "a");
        assert_eq!(out[1]["action"], "b");
    }

    #[test]
    fn eine_geteilte_nachricht_wird_zusammengesetzt() {
        let mut stream = JsonStream::new();

        assert!(stream.push(br#"{"action":"a","mes"#).is_empty());
        let out = stream.push(br#"sage":"AbCd"}"#);

        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["message"], "AbCd");
    }

    #[test]
    fn der_rest_einer_portion_bleibt_liegen() {
        let mut stream = JsonStream::new();
        let out = stream.push(br#"{"action":"a"}{"action":"#);

        assert_eq!(out.len(), 1);
        assert_eq!(stream.push(br#""b"}"#)[0]["action"], "b");
    }

    #[test]
    fn leerraum_zwischen_nachrichten_stoert_nicht() {
        let mut stream = JsonStream::new();
        assert_eq!(stream.push(b" {\"a\":1}\n\n {\"a\":2} ").len(), 2);
    }
}
