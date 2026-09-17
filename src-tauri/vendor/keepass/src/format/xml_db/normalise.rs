//! Gleichnamige Geschwister zusammenziehen, bevor serde das XML liest.
//!
//! # Warum das nötig ist
//!
//! `quick-xml` sammelt wiederholte Elemente nur dann in einen `Vec`, wenn
//! sie **lückenlos aufeinander folgen**. Steht irgendetwas dazwischen,
//! bricht die Deserialisierung mit `duplicate field` ab:
//!
//! ```text
//! <String/><String/>                 → Ok
//! <String/><Binary/><String/>        → Err("duplicate field `String`")
//! ```
//!
//! In echten KDBX-Dateien kommt genau das vor: Sobald ein Eintrag einen
//! Anhang trägt, schreiben manche Programme `<Binary>` zwischen die
//! `<String>`-Felder. KeePassXC, KeePassDX und KeePassium stört das nicht,
//! diese Bibliothek schon.
//!
//! # Was hier passiert
//!
//! Das XML wird einmal durchlaufen und jedes Element so umsortiert, dass
//! gleichnamige Kinder beieinanderstehen. Die **erste** Position eines
//! Namens bleibt erhalten, damit die Reihenfolge im Übrigen so bleibt, wie
//! sie war:
//!
//! ```text
//! A B A C B   →   A A B B C
//! ```
//!
//! Inhalte werden dabei nicht angefasst — nur die Reihenfolge der
//! Geschwister. Für das Datenmodell ist sie bedeutungslos: Welches Feld
//! wohin gehört, steht in `<Key>`, nicht in der Position.
//!
//! Der geschützte Stream ist davon ebenfalls unberührt, weil er erst nach
//! dem Einlesen entschlüsselt wird — und zwar in der Reihenfolge, in der
//! die Werte im Baum stehen, nicht im Text.

use std::io::Cursor;

use quick_xml::events::{BytesEnd, BytesStart, Event};
use quick_xml::{Reader, Writer};

/// Ein Element mit allem, was darin steht.
struct Node<'a> {
    name: Vec<u8>,
    start: BytesStart<'a>,
    /// Alles zwischen Anfang und Ende, roh.
    inner: Vec<Event<'a>>,
    /// Selbstschließend, also ohne eigenes Ende-Ereignis.
    empty: bool,
}

/// Zieht gleichnamige Geschwister zusammen.
///
/// Schlägt das Umschreiben fehl, wird das ursprüngliche XML
/// zurückgegeben — lieber der bekannte Fehler als ein zerstörter Baum.
pub fn group_repeated_siblings(data: &[u8]) -> Vec<u8> {
    rewrite(data).unwrap_or_else(|_| data.to_vec())
}

fn rewrite(data: &[u8]) -> Result<Vec<u8>, quick_xml::Error> {
    let mut reader = Reader::from_reader(data);
    reader.config_mut().trim_text(false);

    let mut writer = Writer::new(Cursor::new(Vec::new()));
    let mut stack: Vec<Vec<Node<'static>>> = vec![Vec::new()];
    let mut open: Vec<(Vec<u8>, BytesStart<'static>)> = Vec::new();

    loop {
        match reader.read_event()? {
            Event::Eof => break,

            Event::Start(start) => {
                open.push((start.name().as_ref().to_vec(), start.to_owned()));
                stack.push(Vec::new());
            }

            Event::End(_) => {
                let children = stack.pop().unwrap_or_default();
                let Some((name, start)) = open.pop() else { continue };

                let node = Node {
                    name,
                    start,
                    inner: flatten(sort_by_first_appearance(children)),
                    empty: false,
                };

                push(&mut stack, node);
            }

            Event::Empty(start) => {
                let node = Node {
                    name: start.name().as_ref().to_vec(),
                    start: start.to_owned(),
                    inner: Vec::new(),
                    empty: true,
                };
                push(&mut stack, node);
            }

            // Text, Kommentare, Deklaration: unverändert an Ort und Stelle.
            other => {
                if let Some(level) = stack.last_mut() {
                    level.push(Node {
                        name: Vec::new(),
                        start: BytesStart::new(""),
                        inner: vec![other.into_owned()],
                        empty: true,
                    });
                }
            }
        }
    }

    for event in flatten(sort_by_first_appearance(stack.pop().unwrap_or_default())) {
        writer.write_event(event)?;
    }

    Ok(writer.into_inner().into_inner())
}

fn push(stack: &mut [Vec<Node<'static>>], node: Node<'static>) {
    if let Some(level) = stack.last_mut() {
        level.push(node);
    }
}

/// Sortiert so um, dass gleiche Namen zusammenstehen — an der Stelle, an
/// der der Name zum ersten Mal auftauchte.
fn sort_by_first_appearance(nodes: Vec<Node<'static>>) -> Vec<Node<'static>> {
    let mut order: Vec<Vec<u8>> = Vec::new();
    let mut buckets: Vec<Vec<Node<'static>>> = Vec::new();

    for node in nodes {
        // Namenlose Knoten sind Text und Ähnliches — die bleiben, wo sie sind.
        if node.name.is_empty() {
            order.push(Vec::new());
            buckets.push(vec![node]);
            continue;
        }

        match order.iter().position(|n| *n == node.name) {
            Some(at) => buckets[at].push(node),
            None => {
                order.push(node.name.clone());
                buckets.push(vec![node]);
            }
        }
    }

    buckets.into_iter().flatten().collect()
}

fn flatten(nodes: Vec<Node<'static>>) -> Vec<Event<'static>> {
    let mut out = Vec::new();

    for node in nodes {
        if node.name.is_empty() {
            out.extend(node.inner);
            continue;
        }

        if node.empty {
            out.push(Event::Empty(node.start));
            continue;
        }

        let end = BytesEnd::new(String::from_utf8_lossy(&node.name).into_owned());
        out.push(Event::Start(node.start));
        out.extend(node.inner);
        out.push(Event::End(end));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::group_repeated_siblings;

    fn text(xml: &str) -> String {
        String::from_utf8(group_repeated_siblings(xml.as_bytes())).unwrap()
    }

    #[test]
    fn zieht_getrennte_zusammen() {
        assert_eq!(
            text("<E><S>a</S><B>x</B><S>b</S></E>"),
            "<E><S>a</S><S>b</S><B>x</B></E>"
        );
    }

    #[test]
    fn laesst_zusammenhaengende_in_ruhe() {
        let xml = "<E><S>a</S><S>b</S><B>x</B></E>";
        assert_eq!(text(xml), xml);
    }

    #[test]
    fn wirkt_auch_in_der_tiefe() {
        assert_eq!(
            text("<Root><G><S>a</S><B/><S>b</S></G></Root>"),
            "<Root><G><S>a</S><S>b</S><B/></G></Root>"
        );
    }

    #[test]
    fn behaelt_attribute_und_leere_elemente() {
        assert_eq!(
            text(r#"<E><V k="1"/><B/><V k="2"/></E>"#),
            r#"<E><V k="1"/><V k="2"/><B/></E>"#
        );
    }
}
