# WKeePass

Passwortverwaltung für KeePass-Datenbanken (KDBX) — für Linux, Windows,
macOS und Android. Öffnet und schreibt dieselben Dateien wie KeePassXC und
KeePassDX, gleicht Änderungen anderer Geräte über die Cloud ab, kann
2FA-Codes, Passkeys, Autofill und den Browser.

Gebaut mit Tauri 2: Der Kern in Rust verwahrt alle Geheimnisse, die
Oberfläche (HTML, CSS, JavaScript ohne Bundler) sieht nur Namen und
Platzhalter. Warum das so ist und wie die Teile zusammenspielen, steht in
[CONTEXT.md](CONTEXT.md).

---

## Was die App kann

| Bereich | Was | Wo im Code |
|---|---|---|
| Datenbank | KDBX 4 öffnen und schreiben, Schlüsseldatei, fünf Stufen der Verschlüsselungsstärke | `database.rs`, `pages/settings.js` |
| Entsperren | Master-Passwort, App-PIN, Fingerabdruck/Gesicht, Geräteschlüssel (Windows Hello u. a.) | `seal.rs`, `biometric.rs`, `keystore.rs`, `pages/lock.js` |
| Einträge | Ordner als aufklappbare Gruppen, Tags, Ziehen zum Umsortieren, Mehrfachauswahl | `entries.rs`, `pages/entries.js`, `ui/dragmove.js`, `ui/multiselect.js` |
| Papierkorb | eigener Block unter den Einträgen; nach 30 Tagen endgültig weg | `state.rs`, `pages/entries.js` |
| 2FA | TOTP-Codes, QR-Code per Kamera oder aus einem Bild, Sammelexporte (Google Authenticator) | `secrets.rs`, `qr.rs`, `pages/totp.js`, `dialogs/create.js` |
| Passkeys | WebAuthn-Schlüssel in der Datenbank, auf Android über den Credential Manager | `passkey.rs`, `android_services.rs` |
| Dateien | Anhänge verschlüsselt ablegen, mit Vorschau (Bild, PDF, Text, Markdown) | `dialogs/entry.js`, `data/preview.js` |
| Abgleich | dieselbe Datei auf mehreren Geräten, Zusammenführen Eintrag für Eintrag | `database.rs`, `storage.rs` |
| Versionen | die letzten 20 Stände, jeder sagt, was er geändert hat; zurücknehmen | `versions.rs`, `dialogs/versions.js` |
| Offline | Kopie jeder geöffneten Datei, falls die Cloud gerade nicht erreichbar ist | `offline.rs` |
| Browser | Anbindung an die Erweiterung keepassxc-browser (Firefox, Chrome, Edge …) | `keepass_extension/`, `pages/request.js` |
| Android | Autofill, Passkeys, Datenbank über die Dateiauswahl (Nextcloud, Drive) | `android_services.rs`, `keepass-android/` |
| Sicherheitscheck | schwache, mehrfach genutzte, abgelaufene und geleakte Passwörter (HIBP, k-Anonymität) | `pages/checkup.js`, `data/security.js` |
| Import | 2FAS, Aegis, andOTP, Bitwarden, KeePass-XML, Proton Pass/Authenticator, CSV mit eigener Spaltenzuordnung | `data/import.js`, `dialogs/create.js` |
| Website-Icons und -Namen | einmal holen, dann in der Datenbank | `favicon.rs`, `web.rs` |

---

## Aufbau

```
src-tauri/          der Kern (Rust) — Bauhinweise in src-tauri/README.md
  src/              ein Modul je Aufgabe, siehe unten
  examples/         Werkzeuge zum Ausprobieren: Test-Datenbanken anlegen und von außen ändern
  vendor/keepass/   die KDBX-Bibliothek mit unseren Korrekturen
src-ui/             die Oberfläche
  index.html        die App, request.html das kleine Fenster für Browser-Anfragen
  js/app.js         Start und die Ereignisse, die immer gelten
  js/core/          was alle Seiten brauchen: Zustand, Zeichnen, Navigation, Plattform
  js/data/          Daten: Kern-Anbindung, Einstellungen, Import, Sicherheit, Demo-Kern
  js/ui/            Bausteine: Dialoge (wuefl-libs), Formulare, Zwischenablage, Ziehen
  js/pages/         je Seite eine Datei
  js/dialogs/       die größeren Dialoge
  css/app.css       Stil (nested CSS, Variablen für wuefl-libs)
  libs/             Verweis auf wuefl-libs (Nachbarprojekt)
keepass-android/    Kotlin für Autofill und Passkeys — eingebunden von tools/android-einbinden.py
appdata/            Neuigkeiten, Symbole, Screenshots, Werbebilder, Store-Texte, version.py
flatpak/            Flatpak-Manifest und Metainfo
tests/              alle Tests, siehe unten
tools/              Hilfsskripte: Android-Bau, Symbole, Web-Demo, Entwicklungsserver
```

### Oberfläche (`src-ui/js/`)

| Datei | Aufgabe |
|---|---|
| `app.js` | Start, Anmeldung der Seiten zum Zeichnen, Abgleich-Auslöser, Anfragen aus dem Browser, feste Ereignisse |
| `core/state.js` | was die ganze Oberfläche gemeinsam weiß (`state`, `$`, `esc`) |
| `core/render.js` | der Mittelpunkt des Zeichnens (`seite`, `zeichne`, `renderAll`), Neuladen aus dem Kern, Abgleich |
| `core/entries.js` | kleine Auskünfte über Einträge: abgelaufen, Datei, zuletzt genutzt |
| `core/navigation.js` | welche Ansicht gerade zu sehen ist |
| `core/platform.js` | die einzige Tür zum Kern (`invoke`), Dateiauswahl |
| `core/theme.js`, `core/icons.js` | Farbschema und Akzentfarbe; Website-Icons |
| `data/vault.js` | die Grenze zum Datenbankkern |
| `data/settings.js` | Einstellungen mit Voreinstellungen aus `config/settings.default.json` |
| `data/demo.js` | Ersatzkern für den Browser ohne Rust (Entwicklung, Tests, Web-Demo) |
| `data/import.js`, `data/security.js`, `data/totp.js`, `data/qr.js`, `data/preview.js`, `data/attachments.js` | Import, Sicherheitscheck, TOTP, QR, Vorschau, Anhänge |
| `ui/libs.js` | die einzige Stelle, die wuefl-libs kennt (Dialog, Meldungen, Tabelle) |
| `ui/formular.js`, `ui/clipboard.js`, `ui/dragmove.js`, `ui/multiselect.js` | Formulare, Kopieren mit Aufräumen, Ziehen, Mehrfachauswahl |
| `pages/home.js`, `pages/entries.js`, `pages/totp.js`, `pages/checkup.js` | Übersicht, Einträge (mit Papierkorb), 2FA, Sicherheitscheck |
| `pages/lock.js` | Sperrbildschirm, Entsperren, App-PIN, Willkommen, neue Datenbank |
| `pages/settings.js` | Einstellungen samt Android-, Datenbank- und Browser-Abschnitt |
| `pages/request.js` | das kleine Fenster für Anfragen aus dem Browser |
| `dialogs/entry.js`, `dialogs/folder.js` | Eintrag (mit Anhängen und Vorschau), Ordner |
| `dialogs/versions.js` | Versionen: die Liste und was ein Stand geändert hat |
| `dialogs/create.js` | „Neu anlegen": Eintrag, Dateien, Ordner, Import, QR-Code |

### Kern (`src-tauri/src/`)

| Datei | Aufgabe |
|---|---|
| `lib.rs` | Start, Fenster, alle Befehle der Oberfläche |
| `database.rs` | öffnen, lesen, zurückschreiben, zusammenführen, Abgleich, Verschlüsselungsstärke |
| `entries.rs` | Einträge und Ordner ändern, Papierkorb |
| `state.rs` | Zustand des Kerns, Gruppenbaum ↔ Ordnerpfad, Papierkorb-Frist |
| `versions.rs` | die letzten Stände, Vergleich, Zurückholen |
| `storage.rs` | lesen und schreiben, auch `content://` auf Android |
| `offline.rs` | Offline-Kopie jeder geöffneten Datei |
| `secrets.rs` | Geheimnisse verwahren, TOTP, Passwortstärke |
| `seal.rs`, `keystore.rs`, `biometric.rs` | App-PIN, Schlüssel im Schlüsselbund, Nachweis des Besitzers |
| `passkey.rs` | Passkeys (WebAuthn) |
| `keepass_extension/` | Anbindung an keepassxc-browser: Protokoll, Verschlüsselung, Verteiler |
| `android_services.rs`, `java.rs` | Autofill und Passkeys auf Android, der Weg zur Java-Seite |
| `matching.rs` | welcher Eintrag zu welcher Adresse passt |
| `favicon.rs`, `web.rs` | Website-Icons und -Titel |
| `qr.rs` | QR-Codes lesen |
| `settings.rs`, `system.rs`, `webview.rs`, `util.rs`, `dto.rs` | Einstellungsdatei, Betriebssystem, Webview, Kleinkram, Typen an der Grenze |

---

## Abgleich zwischen Geräten

Die Datei liegt in einem Ordner, den die Cloud abgleicht (Nextcloud, Drive …), und jedes Gerät öffnet
dieselbe Datei. WKeePass sieht nach, sobald die App nach vorn kommt und danach jede Minute; vor jedem
Speichern wird die Datei noch einmal gelesen. Hat ein anderes Gerät inzwischen geschrieben, werden beide
Stände Eintrag für Eintrag zusammengeführt: Die jüngere Änderung gilt, die ältere bleibt im Verlauf des
Eintrags, Gelöschtes bleibt gelöscht. Lässt sich die Datei gerade nicht lesen, wird nicht geschrieben —
die Änderungen bleiben in der App.

## Versionen

Die letzten 20 Stände der Datei bleiben auf dem Gerät, verschlüsselt wie das Original: beim Öffnen, bei
jedem Speichern und jedes Mal, bevor der Stand eines anderen Geräts eingemischt wird. Unter
*Einstellungen → Datenbank → Versionen* steht unter jedem Stand, was er gegenüber dem davor geändert hat —
die Liste liest sich wie ein Verlauf. Ein Stand lässt sich öffnen; dort nimmt „Zurücknehmen" eine einzelne
Änderung zurück, „Ganz auf diesen Stand zurück" setzt alle Einträge so, wie sie damals waren.

## Papierkorb

Gelöschtes wandert erst in den Papierkorb. Der steht als eigener Block unter den Einträgen, zugeklappt,
und sagt je Eintrag, wann er endgültig verschwindet: Beim Öffnen der Datenbank wird entfernt, was länger
als 30 Tage drinliegt — mit Löschvermerk, damit kein anderes Gerät es zurückbringt.

---

## Entwickeln

```
tools/demo-web.sh               die Oberfläche im Browser, mit dem Demo-Kern (ohne Rust)
cd src-tauri && cargo tauri dev die App mit dem echten Kern
tauri-android keepass install   Android-Debugfassung bauen und aufs Handy (neben der echten App)
```

Zum Ausprobieren nie die echte Datenbank nehmen:

```
cargo run --example testdatenbank -- /tmp/test.kdbx 1234                 klein, vier Einträge
cargo run --example testdatenbank -- --beispiel /tmp/beispiel.kdbx 1234  die Demodaten als echte KDBX
cargo run --example dbwerkzeug -- DATEI 1234 ls|neu|setze|weg …          von außen ändern, wie ein anderes Gerät
```

## Tests

```
tests/all.sh                    alles: Kern, Module, Oberfläche
tests/all.sh --ohne-rust        nur der Browser-Teil
tests/rust.sh [name]            Tests des Kerns (cargo test)
tests/einheit/lauf.sh [name]    Modultests im Browser, eine Datei je Modul
tests/oberflaeche/02-entsperren.sh   eine Klickfolge durch die Demo
```

Die Browser-Tests starten die Oberfläche ohne Tauri; die Antworten kommen aus `js/data/demo.js`. Die
Konsole der Seite kommt als Text heraus, ein Fehler macht den Lauf rot. Was zwei Geräte und eine Cloud
braucht — der Abgleich —, wird mit `examples/dbwerkzeug.rs` von Hand geprüft.

## Veröffentlichen

Die Version steht im obersten Eintrag von `appdata/messages.json`; `python3 appdata/version.py` trägt sie in
`tauri.conf.json`, `Cargo.toml`, `Cargo.lock` und die Flatpak-Metainfo ein. Gebaut wird über GitHub Actions
(`.github/workflows/build.yml`) für Linux, Windows, macOS und Android, sobald ein Tag `vX.Y.Z` kommt.

## Lizenz

Apache License 2.0 — siehe [LICENSE](LICENSE) und [NOTICE](NOTICE).

Du darfst WKeePass frei nutzen, verändern und weitergeben, auch
kommerziell.

## Spende

Nutzt du WKeePass kommerziell oder baust es in ein kommerzielles Produkt
ein, freue ich mich über eine kleine Spende. Das ist eine Bitte, keine
Bedingung der Lizenz.
