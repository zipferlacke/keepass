//! Reproduziert den Fehler „duplicate field `String`" beim Öffnen.
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Entry {
    #[serde(default, rename = "String")]
    string_fields: Vec<Feld>,
    #[serde(default, rename = "Binary")]
    binary_fields: Vec<Feld>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Feld { key: String }

#[test]
fn zusammenhaengend() {
    let xml = "<Entry><String><Key>a</Key></String><String><Key>b</Key></String></Entry>";
    println!("zusammenhängend      -> {:?}", quick_xml::de::from_str::<Entry>(xml).map(|e| e.string_fields.len()));
}

#[test]
fn unterbrochen() {
    let xml = "<Entry><String><Key>a</Key></String><Binary><Key>x</Key></Binary><String><Key>b</Key></String></Entry>";
    println!("durch Binary getrennt -> {:?}", quick_xml::de::from_str::<Entry>(xml).map(|e| e.string_fields.len()));
}

#[test]
fn unbekanntes_dazwischen() {
    let xml = "<Entry><String><Key>a</Key></String><Fremd>x</Fremd><String><Key>b</Key></String></Entry>";
    println!("durch Unbekanntes     -> {:?}", quick_xml::de::from_str::<Entry>(xml).map(|e| e.string_fields.len()));
}

/// Was steht in einem echten KeePassXC-Eintrag zwischen den String-Feldern?
#[test]
fn anhang_dazwischen() {
    // So schreibt KeePassXC einen Eintrag mit Anhang und zusätzlichem Feld:
    let xml = "<Entry>\
        <String><Key>Notes</Key></String>\
        <String><Key>Password</Key></String>\
        <Binary><Key>datei.pdf</Key></Binary>\
        <String><Key>Title</Key></String>\
        </Entry>";
    println!("Anhang zwischen Feldern -> {:?}", quick_xml::de::from_str::<Entry>(xml).map(|e| e.string_fields.len()));
}

/// Und wenn man die Reihenfolge vorher glattzieht?
#[test]
fn nach_sortierung() {
    let xml = "<Entry>\
        <String><Key>Notes</Key></String>\
        <String><Key>Password</Key></String>\
        <String><Key>Title</Key></String>\
        <Binary><Key>datei.pdf</Key></Binary>\
        </Entry>";
    println!("nach dem Gruppieren     -> {:?}", quick_xml::de::from_str::<Entry>(xml).map(|e| e.string_fields.len()));
}
