# WKeePass — der Kern

Die Architektur, die Kommandoliste und der Stand stehen in `../CONTEXT.md`.
Hier nur, was beim Bauen zu beachten ist.

## Warum `src-tauri` und `src-ui` Geschwister sind

`tauri::generate_context!()` bettet **alle** Dateien unter `frontendDist` in
die Binärdatei ein — ohne jede Ausnahme, auch `target/`. Lag `src-tauri`
innerhalb des Frontend-Verzeichnisses und zeigte `frontendDist` auf dessen
Elternordner, dann las der Compiler das eigene Build-Verzeichnis in sich
selbst hinein. Bei elf Gigabyte bleibt `cargo check` dann scheinbar grundlos
bei „Building 669/671" stehen — das ist die Makroexpansion, nicht das
Typprüfen.

`frontendDist` muss deshalb auf ein Verzeichnis zeigen, das **nur** das
Frontend enthält — hier `../src-ui`.

Eine Liste statt eines Verzeichnisses hilft nicht: Tauri legt dabei alle
Dateien flach in die Wurzel, `js/app.js` würde zu `app.js`.

## Module

| Datei | Zweck |
|---|---|
| `lib.rs` | Plugins und Kommandoregistrierung, sonst nichts |
| `dto.rs` | die Typen, die über die IPC-Grenze gehen |
| `state.rs` | `VaultState`, Token-Tabelle, Gruppenbaum ↔ Ordnerpfad |
| `database.rs` | entsperren, auslesen, zurückschreiben |
| `entries.rs` | Einträge und Ordner ändern |
| `secrets.rs` | Werte verwahren, Stärke, Hash, TOTP, Anhänge |
| `seal.rs` | Master-Passwort unter einer PIN versiegeln |
| `settings.rs` | `settings.json` im Konfigurationsverzeichnis |
| `system.rs` | Dateiauswahl, Seitentitel |
| `qr.rs` | QR-Dekodierung mit [`rqrr`](https://crates.io/crates/rqrr) |
| `util.rs` | `write_atomic` |

## Warum die `keepass`-Crate

Sie liest und schreibt KDBX 3.1 und 4 und bringt Argon2, AES, ChaCha20 und
den inneren Stream mit. Was sie **nicht** kann: KDBX 3.1 schreiben.

Beim Speichern serialisiert sie aus ihrem Objektmodell. Erhalten bleiben alle
String-Felder, CustomData auf Eintrags- und Gruppenebene, AutoType, History,
Icons und Anhänge — und damit auch die Passkey-Felder von KeePassXC
(`KPEX_PASSKEY_*`). Verloren gehen XML-Elemente, die sie nicht modelliert.

Wie viel das an einer echten Datei ausmacht, prüft man mit `kp-rewrite` aus
der Crate: öffnen, speichern, das Ergebnis mit dem Original vergleichen. Das
sollte passiert sein, bevor `vault_commit` auf eine Datei losgelassen wird,
die auch KeePassXC anfasst.

## Bauen

```bash
cargo install tauri-cli --version "^2"

cargo tauri dev
cargo tauri build
```

Unter Fedora (auch Asahi/aarch64):

```bash
sudo dnf install webkit2gtk4.1-devel openssl-devel curl wget file \
                 libappindicator-gtk3-devel librsvg2-devel gcc gcc-c++
```

Für den modernen GNOME-Dateidialog statt des alten GTK3-Fensters ist
`tauri-plugin-dialog` bereits mit `features = ["xdg-portal"]` eingebunden.

## Was noch fehlt

- `vault_store_attachment` — in KDBX gehört ein Anhang immer zu einem
  Eintrag. Die Oberfläche legt ihn aber ab, bevor der Eintrag gespeichert
  wird. Dafür braucht es eine Zwischenablage im Kern, die `vault_save_entry`
  auflöst.
- Reihenfolge innerhalb eines Ordners — `Group::entries` ist crate-intern,
  deshalb setzen `vault_reorder_*` nur den Zielordner durch.
- `fetch_page_title` — braucht `reqwest` mit Zeitlimit, begrenzten
  Weiterleitungen und gedeckelter Antwortgröße.
- Biometrie — unter Windows gerätegebunden über Windows Hello (`device.json`,
  ersetzt PIN und Master-Passwort). macOS fehlt noch der Keychain-Eintrag mit
  `SecAccessControl`; dort und unter Linux bleibt es ein Ja/Nein. Siehe
  `biometric.rs` und `seal.rs`. Der Windows-Teil ist bisher weder unter Windows
  übersetzt noch auf einem echten Gerät ausprobiert.
- Fremdänderung erkennen: beim Öffnen den SHA-256 der Datei merken und vor
  `write_atomic` erneut prüfen. Die Datei liegt in Nextcloud und wird parallel
  von KeePassXC angefasst.
