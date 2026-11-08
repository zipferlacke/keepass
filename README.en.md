# WKeePass

[Deutsch](README.md) · **English**

Password manager for KeePass databases (KDBX) — for Linux, Windows,
macOS and Android. Opens and writes the same files as KeePassXC and
KeePassDX, syncs changes from other devices via the cloud, and handles
2FA codes, passkeys, autofill and the browser.

For anyone who wants to check for themselves: the [technical documentation](https://wuefl.de/wkeepass/en/doku.html) and
[Security in detail](https://wuefl.de/wkeepass/en/sicherheit.html) – cryptography, threat model and what
the program sends over the network.

Built with Tauri 2: the core, written in Rust, holds all secrets; the
interface (HTML, CSS, JavaScript without a bundler) only sees names and
placeholders. Why it is built this way and how the parts fit together is
described in [CONTEXT.md](CONTEXT.md) (in German).

---

## What the app can do

| Area                     | What                                                                                                                                                                                | Where in the code                                                       |
|--------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------|
| Database                 | Open and write KDBX 4, key file, six levels of encryption strength (default 16 MiB, also opens on an iPhone/iPad)                                                                   | `database.rs`, `pages/settings.js`                                      |
| Unlock                   | Master password, app PIN, fingerprint/face, device key (Windows Hello etc.)                                                                                                         | `seal.rs`, `biometric.rs`, `keystore.rs`, `pages/lock.js`               |
| Entries                  | Folders as collapsible groups (empty ones too), tags, drag to reorder, multi-select, cut and paste                                                                                  | `entries.rs`, `pages/entries.js`, `ui/dragmove.js`, `ui/multiselect.js` |
| Keyboard                 | Ctrl+N, Ctrl+F, type to search, arrows, Enter, Del, Ctrl+X/V (see below)                                                                                                           | `pages/tasten.js`                                                       |
| Recycle Bin              | Its own block below the entries; permanently gone after 30 days                                                                                                                     | `state.rs`, `pages/entries.js`                                          |
| 2FA                      | TOTP codes, QR code via camera or from an image, bulk exports (Google Authenticator)                                                                                                | `secrets.rs`, `qr.rs`, `pages/totp.js`, `dialogs/create.js`             |
| Passkeys                 | WebAuthn keys in the database, on Android via the Credential Manager                                                                                                                | `passkey.rs`, `android_services.rs`                                     |
| Files                    | Store attachments encrypted, with preview (image, PDF, text, Markdown)                                                                                                              | `dialogs/entry.js`, `data/preview.js`                                   |
| Sync                     | The same file on several devices; the app works with its own copy, the file is fetched, merged and written in the background; conflicts are left for you to decide                  | `database.rs`, `konflikt.rs`, `dialogs/konflikte.js`                    |
| Versions                 | The last 30–100 versions (adjustable), each saying what it changed – after a merge, with its origin; revert individually or entirely                                                | `versions.rs`, `dialogs/versions.js`                                    |
| Offline                  | Its own copy of every opened file: opening is instant from it, and changes land there first                                                                                         | `offline.rs`                                                            |
| Browser                  | Connection to the keepassxc-browser extension (Firefox, Chrome, Edge …); if the browser starts WKeePass, it runs in the background without a main window (icon in the tray) and exits with the last browser; on request it asks you to unlock a locked database as soon as the browser starts; passkeys and clicking the field icon ask you to unlock a locked database first, a mere page visit does not; passkeys always require verification, 2FA codes only go out after a prompt | `keepass_extension/`, `pages/request.js`                                |
| Android                  | Autofill, passkeys, database via the file picker (Nextcloud, Drive); if the app is not running, it starts only briefly and unlocking happens in the sheet above the calling app     | `android_services.rs`, `keepass-android/`                               |
| Security check           | Weak, reused, expired and leaked passwords (HIBP, k-anonymity)                                                                                                                      | `pages/checkup.js`, `data/security.js`                                  |
| Import                   | 2FAS, Aegis, andOTP, Bitwarden, KeePass XML, Proton Pass/Authenticator, CSV with your own column mapping                                                                            | `data/import.js`, `dialogs/create.js`                                   |
| Languages                | German, English, Français, Dansk, Norsk bokmål, Polski, Svenska – device language or chosen in the settings; one file per language, organised by page and section; store texts likewise | `core/i18n.js`, `appdata/lang/`, `appdata/store/`                       |
| Website icons and names  | Fetched once, then kept in the database                                                                                                                                             | `favicon.rs`, `web.rs`                                                  |

---

## Structure

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
  lang/             Verweis auf appdata/lang (die Sprachdateien)
keepass-android/    Kotlin für Autofill und Passkeys — eingebunden von tools/android-einbinden.py
appdata/            Neuigkeiten, Sprachdateien (lang/), Symbole, Screenshots, Werbebilder, Store-Texte je Sprache, version.py
flatpak/            Flatpak-Manifest und Metainfo
tests/              alle Tests, siehe unten
tools/              Hilfsskripte: Android-Bau, Symbole, Web-Demo, Entwicklungsserver
```

### Interface (`src-ui/js/`)

| File                                                                                                         | Purpose                                                                                                 |
|--------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------|
| `app.js`                                                                                                     | Start-up, registering pages for rendering, sync triggers, requests from the browser, fixed events       |
| `core/state.js`                                                                                              | What the whole interface knows in common (`state`, `$`, `esc`)                                          |
| `core/render.js`                                                                                             | The hub of rendering (`seite`, `zeichne`, `renderAll`), reloading from the core, sync                   |
| `core/entries.js`                                                                                            | Small queries about entries: expired, file, last used                                                   |
| `core/navigation.js`                                                                                         | Which view is currently shown                                                                           |
| `core/platform.js`                                                                                           | The single door to the core (`invoke`), file picker                                                     |
| `core/theme.js`, `core/icons.js`                                                                             | Colour scheme and accent colour; website icons                                                          |
| `data/vault.js`                                                                                              | The boundary to the database core                                                                       |
| `data/settings.js`                                                                                           | Settings with defaults from `config/settings.default.json`                                              |
| `data/demo.js`                                                                                               | Stand-in core for the browser without Rust (development, tests, web demo)                               |
| `data/import.js`, `data/security.js`, `data/totp.js`, `data/qr.js`, `data/preview.js`, `data/attachments.js` | Import, security check, TOTP, QR, preview, attachments                                                  |
| `ui/libs.js`                                                                                                 | The only place that knows wuefl-libs (dialog, messages, table)                                          |
| `ui/formular.js`, `ui/clipboard.js`, `ui/dragmove.js`, `ui/multiselect.js`                                   | Forms, copying with clean-up, dragging, multi-select                                                    |
| `ui/aufdecken.js`                                                                                            | Revealed password fields as real text fields — otherwise the phone keyboard offers no copy              |
| `pages/tasten.js`                                                                                            | Operating the list with the keyboard                                                                    |
| `pages/home.js`, `pages/entries.js`, `pages/totp.js`, `pages/checkup.js`                                     | Overview, entries (with Recycle Bin), 2FA, security check                                               |
| `pages/lock.js`                                                                                              | Lock screen, unlock, app PIN, welcome, new database                                                     |
| `pages/settings.js`                                                                                          | Settings, including the Android, database and browser sections                                          |
| `pages/request.js`                                                                                           | The small window for requests from the browser                                                          |
| `dialogs/entry.js`, `dialogs/folder.js`                                                                      | Entry (with attachments and preview), folder                                                            |
| `dialogs/versions.js`                                                                                        | Versions: the list and what a version changed                                                           |
| `dialogs/create.js`                                                                                          | "Create new": entry, files, folder, import, QR code                                                     |

### Core (`src-tauri/src/`)

| File                                                          | Purpose                                                                          |
|---------------------------------------------------------------|----------------------------------------------------------------------------------|
| `lib.rs`                                                      | Start-up, windows, all commands of the interface                                 |
| `database.rs`                                                 | Open, read, write back, merge, sync, encryption strength                         |
| `entries.rs`                                                  | Change entries and folders, Recycle Bin                                          |
| `state.rs`                                                    | State of the core, group tree ↔ folder path, Recycle Bin retention period        |
| `versions.rs`                                                 | The last versions, comparison, restoring                                         |
| `storage.rs`                                                  | Reading and writing, including `content://` on Android                           |
| `offline.rs`                                                  | Offline copy of every opened file                                                |
| `secrets.rs`                                                  | Holding secrets, TOTP, password strength                                         |
| `seal.rs`, `keystore.rs`, `biometric.rs`                      | App PIN, key in the keyring, proof of ownership                                  |
| `passkey.rs`                                                  | Passkeys (WebAuthn)                                                              |
| `keepass_extension/`                                          | Connection to keepassxc-browser: protocol, encryption, dispatcher                |
| `android_services.rs`, `java.rs`                              | Autofill and passkeys on Android, the route to the Java side                     |
| `matching.rs`                                                 | Which entry matches which address                                                |
| `favicon.rs`, `web.rs`                                        | Website icons and titles                                                         |
| `qr.rs`                                                       | Reading QR codes                                                                 |
| `settings.rs`, `system.rs`, `webview.rs`, `util.rs`, `dto.rs` | Settings file, operating system, webview, odds and ends, types at the boundary   |

---

## Sync between devices

The file lives in a folder that the cloud syncs (Nextcloud, Drive …), and every device opens
the same file. The app always keeps its own, last-saved copy (encrypted like the
file): it opens from that instantly, and every change lands there first. The file at its location is fetched
in parallel – on opening, after every change and otherwise at most every five minutes. If
another device has written in the meantime, both versions are merged entry by entry, and the file
and the app's own copy are written. If the location cannot be reached (on a phone, Nextcloud contacts
its server on every open and waits up to 30 s), the app carries on with its copy and catches up
with the write later. When merging, the more recent change wins, the older one stays in the entry's history, and deleted items
stay deleted. If both sides have changed the same entry differently since the last common
version, the app asks which version should apply (until then the more recent one applies). Database name and description: the more recent one wins. If
another program has changed the encryption (key derivation, algorithm, compression), WKeePass
adopts that on the next save instead of reverting it — unless it was changed here as well. If
the file cannot be read at the moment, nothing is written — the changes stay in the app.

## Keyboard

| Key            | Effect                                                                                  |
|----------------|-----------------------------------------------------------------------------------------|
| Ctrl+N         | New entry, from any view                                                                |
| Ctrl+F         | Go to the entries and into the search field                                             |
| just type      | Searches — in the entries even without clicking into the search field                  |
| ↑ ↓            | Move through folders and entries                                                        |
| Enter          | Open entry, expand or collapse folder (with Shift: including subfolders)                |
| Del            | Delete entry, with confirmation                                                         |
| Ctrl+X, Ctrl+V | Cut entry, paste into the folder of the selected row (also in the context menu)         |
| Esc            | Discard what was cut, otherwise clear the search                                        |

If a dialog is open or the caret is in another field, the keys belong to that field.

## Versions

The last 30 to 100 versions of the file (configurable) are kept on the device, encrypted like the original: on opening, on
every save, and every time before another device's version is merged in. Under
*Settings → Database → Versions*, each version shows what it changed compared with the one before —
the list reads like a history. A version can be opened; there, "Revert" undoes a single
change, and "Restore this version entirely" sets all entries back to how they were at the time.

## Recycle Bin

Deleted items go to the Recycle Bin first. It appears as its own block below the entries, collapsed,
and says for each entry when it will disappear for good: when the database is opened, anything that has been in there for more
than 30 days is removed — with a deletion record, so that no other device brings it back.

---

## Development

```
tools/demo-web.sh               die Oberfläche im Browser, mit dem Demo-Kern (ohne Rust)
cd src-tauri && cargo tauri dev die App mit dem echten Kern
tauri-android keepass install   Android-Debugfassung bauen und aufs Handy (neben der echten App)
```

Never use your real database for trying things out:

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

The browser tests start the interface without Tauri; the responses come from `js/data/demo.js`. The
page's console comes out as text, and an error turns the run red. What needs two devices and a cloud
— the sync — is checked by hand with `examples/dbwerkzeug.rs`.

## Releasing

The version is in the topmost entry of `appdata/messages.json`; `python3 appdata/version.py` writes it into
`tauri.conf.json`, `Cargo.toml`, `Cargo.lock` and the Flatpak metainfo. Builds run through GitHub Actions
(`.github/workflows/build.yml`) for Linux, Windows, macOS and Android as soon as a tag `vX.Y.Z` is pushed.

## Licence

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

You are free to use, modify and redistribute WKeePass, including
commercially.

## Donation

If you use WKeePass commercially or build it into a commercial product,
I would be glad of a small donation. This is a request, not a condition
of the licence.
