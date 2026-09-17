# WKeePass — CONTEXT.md

Passwortmanager als Tauri-2-App. Ziel: Passwörter, TOTP und Passkeys in einer
kdbx-Datei zusammenführen, die parallel auch von KeePassXC (Linux/macOS),
KeePassDX (Android) und KeePassium (iOS) bearbeitet wird. Synchronisiert wird
über WebDAV (Nextcloud auf eigener NAS).

Zielplattform des Entwicklers: **Fedora Asahi Remix auf Apple Silicon (aarch64)**.
Deshalb Tauri statt Electron — WebKitGTK ist ein normales Fedora-Paket, ein
mitgeliefertes Chromium wäre auf aarch64 Gebastel.

---

## Die zentrale Architekturentscheidung

**Geheimnisse bleiben in Rust. Der Webview sieht nur Metadaten und Platzhalter.**

```
Rust      Container ver-/entschlüsseln, Ordner und Einträge verwalten,
          alle Klartextwerte verwahren, TOTP berechnen, Hashes bilden,
          Passwortstärke bewerten
Webview   Darstellung und Bedienung — sonst nichts
```

Ein Eintrag sieht im Webview so aus — **kein `password`-Feld**:

```json
{ "id": "…", "name": "Nextcloud", "username": "florian",
  "hasPassword": true, "passwordToken": "s1",
  "hasTotp": true, "totpToken": "s2", "expires": "2026-08-20" }
```

Klartext gibt es nur über `vault_reveal_secret` auf ausdrückliche Anforderung.
Beim Kopieren gar nicht: `vault_copy_secret` legt den Wert direkt in die
Zwischenablage.

### Alles geht über `invoke`

Es gibt genau **eine** Tür zum Kern: `invoke()` in `js/platform.js`. Darüber
liegt keine Fallunterscheidung mehr, kein zweites Backend, keine
Ersatzimplementierung.

Läuft die App nicht in Tauri, beantwortet `js/demo.js` dieselben Kommandos aus
`config/demo.json`. Die Oberfläche merkt vom Unterschied nichts — sie ruft in
beiden Fällen wortgleich dasselbe auf. Für die App-Version ist `demo.js`
bedeutungslos und darf verschwinden, sobald der Rust-Kern vollständig ist.

### Warum kein XML mehr im Webview

Früher reichte Rust das innere kdbx-XML herüber, `js/kdbx-xml.js` bearbeitete
es per DOM und gab es zurück. Der Grund war, unbekannte Felder zu erhalten.

Aufgegeben, weil der Preis zu hoch war: ein zweiter Datenbank-Parser in
JavaScript, Platzhalter-Token im XML, und die Dokumentreihenfolge des inneren
Stream-Ciphers als ständige Fehlerquelle. Der Kern führt das Objektmodell
jetzt allein, der Webview bekommt fertige Einträge.

Der Erhalt unbekannter Felder wird damit zur Aufgabe des Kerns — die
`keepass`-Crate hält alle String-Felder, CustomData auf Eintrags- und
Gruppenebene, AutoType, History und Anhänge, und dort liegen auch die
Passkey-Felder von KeePassXC (`KPEX_PASSKEY_*`).

### Entsperren liegt vollständig im Kern

Die Oberfläche fragt `unlock_methods`, zeigt die passenden Knöpfe und schickt
einen davon los. Sie orchestriert nichts und kennt keinen Ablauf — welcher
Weg zum Master-Passwort führt, entscheidet der Kern, und das Passwort kommt
dabei nie zurück in den Webview.

Drei Wege:

```
password   Master-Passwort direkt
pin        PIN --Argon2id--> Schlüssel --XChaCha20-Poly1305--> Master-Passwort
biometric  noch nicht angebunden, siehe unten
```

**Warum symmetrisch und nicht RSA.** RSA löst „verschlüsseln darf jeder,
entschlüsseln nur einer". Hier ist beides dieselbe Person; der private
Schlüssel bräuchte denselben Schutz durch PIN oder Fingerabdruck, den wir
ohnehin bauen. Es käme eine Schicht dazu, kein Gewinn.

**Was die PIN kostet.** Eine sechsstellige PIN hat rund 20 Bit. Argon2id
macht jeden Versuch teuer, aber wer die Datei hat, probiert offline. Die
Datenbank ist damit so sicher wie die PIN, nicht mehr wie das
Master-Passwort. Bewusster Handel — KeePassXC, KeePassium und KeePassDX
machen es genauso. Der Fehlversuchszähler stoppt nur Gelegenheitsversuche am
offenen Gerät.

**Warum Biometrie `false` meldet.** Ein Fingerabdrucksensor liefert keinen
Schlüssel, sondern nur ein Ja. Sicher wird das erst durch einen
Schlüsselspeicher, der die Herausgabe an diese Prüfung bindet: Android
Keystore mit `setUserAuthenticationRequired`, iOS/macOS Keychain mit
`SecAccessControl`. Unter Linux gibt es das nicht — `fprintd` sagt über D-Bus
nur wahr oder falsch, und das versiegelte Passwort läge ungeschützt daneben.
Auf Asahi fehlt zusätzlich der Treiber. Ein Fingerabdruck-Knopf, der in
Wahrheit eine ungeschützte Datei liest, wäre eine Lüge an den Nutzer.

### Wuefl-libs

`js/ui.js` ist die einzige Stelle, die wuefl-libs kennt: `userDialog`,
`banner`, `tableview` und `qrcode`. Keine Ersatzimplementierungen — ist die
Bibliothek nicht erreichbar, ist das ein Fehler und soll auffallen. Zum
Umstellen auf die lokale Einbindung wird `BASE` in `js/ui.js` geändert, dazu
die `@import`-Zeile oben in `css/app.css`.

---

## Dateien

**Frontend und Kern sind Geschwister: `src-ui/` und `src-tauri/`.**
`generate_context!()` bettet alles unter `frontendDist` in die Binärdatei ein
— auch `target/`. Läge der Kern im Frontend-Verzeichnis, läse der Compiler
sein eigenes Build-Verzeichnis in sich selbst hinein und bliebe bei
„Building 669/671" scheinbar grundlos stehen.

```
src-ui/
index.html                 Grundgerüst: Navigation, Views, Sperrbildschirm, FAB
css/app.css                alles, natives CSS-Nesting, @layer custom
config/settings.default.json
config/demo.json           Dummy-Datenbank für den Betrieb ohne Rust
build-single.mjs           bündelt die ES-Module zu einer Vorschau-HTML

js/
  app.js       Oberfläche, Zustand, Rendering, Dialoge (größte Datei)
  vault.js     GRENZE zum Kern. Nur noch invoke-Aufrufe plus ein
               Zwischenspeicher, damit die Oberfläche ohne await liest
  platform.js  DIE Tür zum Kern: invoke() → Rust oder demo.js
  demo.js      Ersatzkern ohne Rust, beantwortet dieselben Kommandos
  settings.js  settings.json über settings_read / settings_write
  security.js  Passwortstärke (lokal), HIBP per Hash, XposedOrNot
  totp.js      RFC 6238 (nur für demo.js; in Tauri rechnet Rust)
  theme.js     Hell/Dunkel/System + Akzentfarbe
  icons.js     Favicons direkt von der Zieldomain, fünf Kandidaten
  qr.js        Scannen über decode_qr_bytes, otpauth + Migration
  preview.js   Anhänge: Text, Markdown (eigener Renderer), PDF, Bild
  dragmove.js  Verschieben und Einsortieren per langem Drücken
  ui.js        die einzige Stelle, die wuefl-libs kennt

../src-tauri/src/
  lib.rs       nur Plugins und die Kommandoliste
  dto.rs       alles, was über die IPC-Grenze geht
  state.rs     VaultState, Token-Tabelle, Gruppenbaum ↔ Ordnerpfad
  database.rs  entsperren, auslesen, zurückschreiben
  entries.rs   Einträge und Ordner ändern
  secrets.rs   Werte verwahren, Stärke, Hash, TOTP, Anhänge
  seal.rs      Master-Passwort unter PIN versiegeln
  settings.rs  settings.json
  system.rs    Dateiauswahl, Seitentitel
  qr.rs        QR-Dekodierung mit rqrr
  util.rs      write_atomic
```

---

## Konventionen (unbedingt einhalten)

- **Vanilla JS, keine Frameworks, kein Build-Schritt.** ES-Module, direkt im
  Browser lauffähig.
- **wuefl-libs** wird genutzt, wo möglich: `css/import.css`, `userDialog`,
  `banner`, `tableview`, `qrcode`. Eingebunden von `https://open.wuefl.de/wuefl-libs/`.
- **CSS immer verschachtelt**, alles in `@layer custom`, Variablen `--clr-*`,
  `--fs-*`, `--br-*`. Icon-Knöpfe: `data-shape="square"`.
- **Kommentare und Oberflächentexte auf Deutsch.**
- Module halten ihre Verantwortung sauber getrennt; `vault.js` ist die einzige
  Stelle, die den Kern kennt.

### Fallstricke, die schon Zeit gekostet haben

1. **`data-sort-value`, nicht `data-sortValue`.** HTML kleinschreibt Attribute;
   `tableview` liest `td.dataset.sortValue`, was `data-sort-value` verlangt.
2. **`userDialog` löst sein Promise nur bei Klick auf `.dialog_close` oder
   `.dialog_submit` auf.** Ein direktes `dialog.close()` lässt das `await`
   hängen. Dafür gibt es `closeHostDialog()` in `js/ui.js`.
3. **Zuhörer nicht bei jedem Rendern neu anhängen.** `setupDragMove` lief
   früher pro Rendering und erzeugte Meldungen mehrfach. Jetzt einmalig,
   Aufräumen über `AbortController`.
4. **Keine Rückkopplung Rendern → Einstellung speichern → Rendern.** Genau das
   erzeugte eine Endlosschleife (259 Renderings in 1,5 s, Firefox stürzte ab).
   `settings.set(path, value, { silent: true })` für reine UI-Zustände.
5. **`<details>`-`toggle`-Ereignis feuert auch beim Einfügen ins DOM.** Deshalb
   hängt der Zustandswechsel am `click` der `<summary>`.
6. **Ordner sind standardmäßig zu.** Gemerkt wird `ui.expandedFolders`, nicht
   das Gegenteil.

---

## Stand

### Fertig (Webview)

Sperrbildschirm mit Datenbankwahl und Biometrie-Weiche · Ordnerbaum mit eigener
`tableview`-Tabelle je Ordner · Suche blendet Ordner aus und zeigt flach ·
Ampel-Sortierung (0 rot / 1 orange / 2 grün / 3 grau) · TOTP-Ansicht mit
Einfachklick=kopieren, Doppelklick=öffnen und Vorschau des nächsten Codes in
den letzten 10 s · Sicherheitscheck mit Kennzahlen und direkter Bearbeitung ·
Eintragsdialog mit aufklappbaren Abschnitten und `•••••`-Maskierung ·
QR-Scan inkl. Google-Authenticator-Sammelimport · Anhang-Vorschau ·
Verschieben und Einsortieren per langem Drücken · Kontextmenü · Einstellungen
als JSON mit Export/Import/Zurücksetzen

### Fertig (Rust)

`qr.rs` vollständig · `write_atomic` (Sicherungskopie, `sync_all`, atomares
Umbenennen)

**Der Rust-Teil passt derzeit nicht zur Oberfläche.** `vault.rs` stammt noch
aus der XML-Fassung und registriert `vault_xml` / `vault_commit(xml)`. In
Tauri läuft die App deshalb erst wieder, wenn der Kern die Kommandoliste
unten bedient. Im Browser läuft sie über `demo.js` vollständig.

### Die Kommandoliste — der Vertrag zwischen Oberfläche und Kern

Maßgeblich ist `js/demo.js`: Was dort steht, muss Rust genauso beantworten.

```
Entsperren   unlock_methods → {password,pin,biometric}
             vault_unlock{path,method,secret,keyfile} → {name,path}
             vault_set_pin{pin} · vault_clear_pin

Datenbank    vault_list_entries → Entry[]
             vault_folders → String[]
             vault_commit · vault_lock

Einträge     vault_save_entry{entry} → Entry
             vault_delete_entry{id} · vault_move_entry{id,folder}
             vault_reorder_entry{id,referenceId,position}

Ordner       vault_create_folder{path} · vault_rename_folder{path,name}
             vault_move_folder{path,parent} · vault_remove_folder{path}
             vault_reorder_folder{path,referencePath,position}

Geheimnisse  vault_new_secret{value} → Token · vault_set_secret{token,value}
             vault_drop_secret{token} · vault_reveal_secret{token}
             vault_copy_secret{token}

Auswertung   vault_strength{token} · vault_hash_prefix{token}
             vault_duplicate_groups · vault_totp{token,config}

Anhänge      vault_attachment{ref} · vault_store_attachment{name,type,dataUrl}

System       pick_database_file · fetch_page_title{url}
             settings_read · settings_write{json}

QR           decode_qr_bytes · decode_qr_rgba · decode_qr_path
```

Ein `Entry` trägt genau die Felder aus `config/demo.json`. `folder` ist der
Gruppenpfad als `"Eltern/Kind"`, die Wurzel heißt `"Allgemein"`.

### Offen — in dieser Reihenfolge

**1. Rust zurücksetzen und auf die `keepass`-Crate stellen**
`vault.rs` und `passkey.rs` weg, dafür `state.rs`, `dto.rs`, `database.rs`.
`Database::open` liefert das Objektmodell; beim Öffnen einmal über alle
Einträge laufen und jedes `Value::Protected` als Token ablegen.
`keepass = { version = "0.13", features = ["totp"] }`, `rust-version` auf 1.85.

**2. `settings_read` / `settings_write`** (klein)
Pfad über `app.path().app_config_dir()`, schreiben über `write_atomic`.

**3. Schreiben — Entscheidung steht noch aus**
`Database::save` serialisiert aus dem Objektmodell. Vorher an der echten
Datei prüfen, was das kostet: `kp-rewrite` aus der Crate öffnet und speichert,
das Ergebnis mit dem Original vergleichen. Erst danach `vault_commit`.
Vor dem ersten echten Schreibversuch: Kopie anlegen und danach mit KeePassXC
öffnen.

**4. Kleinkram** (~1 Tag)
`vault_strength` (Logik aus `js/security.js` übersetzen — **Achtung**: die
`COMMON`-Liste wird dort in Einfügereihenfolge durchlaufen und beim ersten
Treffer abgebrochen; in Rust also `&[&str]`, kein `HashSet`, sonst kommen bei
mehreren Treffern andere Abzüge heraus) · `vault_hash_prefix` (SHA-1 hex groß,
`[0..5]`/`[5..]`) · `vault_totp` (über `entry.get_otp()?.value_now()`) ·
`vault_copy_secret` (Plugin `clipboard-manager` ist schon eingebunden) ·
`zeroize` in `vault_lock` · `fetch_page_title` (`reqwest`, Zeitlimit,
Weiterleitungen und Antwortgröße begrenzen)

**5. Biometrie**
Android/iOS `tauri-plugin-biometric` · macOS `LAContext` über `objc2` ·
Linux `fprintd` per D-Bus — auf Asahi mangels Treiber vorerst zwecklos, dort
muss `biometric_available` weiterhin `false` liefern.
Freigeschaltet wird das App-Geheimnis aus dem Schlüsselbund, mit dem das
Master-Passwort entschlüsselt wird — nicht das Master-Passwort selbst.

**6. Passkeys**
ES256-Schlüsselpaare, `attestationObject` (CBOR), `authenticatorData`,
Signaturzähler. Crates: `p256`, `ciborium`, `rand`. Ablage im Ordner
`Passkeys`.
Die Anfrage kommt nie aus der Oberfläche: Desktop über einen
Native-Messaging-Host (Vorbild `keepassxc-proxy-rust`, dokumentiertes
NaCl-Protokoll), Android über einen `CredentialProviderService` in Kotlin.

**7. WebDAV** (nur für Android ohne Nextcloud-Client nötig)
`reqwest` GET/PUT, `ETag` merken, beim Speichern `If-Match`; bei `412` Merge
statt Überschreiben.

---

## Bauen und ausführen

```bash
# Systemabhängigkeiten (Fedora, auch aarch64)
sudo dnf install webkit2gtk4.1-devel openssl-devel gcc gcc-c++ \
                 libappindicator-gtk3-devel librsvg2-devel \
                 xdg-desktop-portal-gtk zenity

cargo install cargo-binstall && cargo binstall tauri-cli   # schneller als cargo install
cd src-tauri && cargo tauri dev
```

`src-tauri/` liegt auf derselben Ebene wie `src-ui/` — siehe oben, sonst
frisst sich `generate_context!()` an `target/` fest.

Für den modernen GNOME-Dateidialog statt des alten GTK3-Fensters in
`Cargo.toml`:

```toml
tauri-plugin-dialog = { version = "2", default-features = false, features = ["xdg-portal"] }
```

### Vorschau ohne Rust

```bash
node build-single.mjs      # erzeugt ../wkeepass-single.html
```

Läuft gegen `js/demo.js` mit den Daten aus `config/demo.json` — kein Passwort
nötig, Feld leer lassen. Beide JSON-Dateien werden dabei ins Bündel
eingebettet, damit kein `fetch` nötig ist.

Weil oberhalb von `invoke()` nichts zwischen echt und Demo unterscheidet, ist
die Vorschau nicht nur ähnlich, sondern nimmt buchstäblich denselben Weg.

---

## Was noch fehlt, ohne dass es jemand gemeldet hat

- Beim Wechsel von Tag-Filter oder Suche geht die aktuelle `tableview`-Sortierung
  verloren (Tabelle wird neu gebaut). Ließe sich beheben, indem der Sortierzustand
  gemerkt und nach dem Rendern wieder gesetzt wird.
- Die Passwörter aus `config/demo.json` stehen im gebündelten Skript im
  Klartext. In Tauri wird `demo.js` nie geladen, aber die Vorschau-HTML
  sollte man nicht öffentlich ausliefern.
- wuefl-libs wird per dynamischem Import von `open.wuefl.de` geladen. Dafür
  braucht die Domain eine CORS-Freigabe für `.js` und Schriftdateien —
  bei lokaler Einbindung im App-Bundle entfällt das. Umzustellen ist dann nur
  `BASE` in `js/ui.js` und die `@import`-Zeile in `css/app.css`.
- Ohne Rust gibt es keinen QR-Scanner mehr (die native `BarcodeDetector`-API
  fehlt in WebKitGTK und Firefox, also genau dort, wo die App läuft). In der
  Vorschau ist der Scanner deshalb abgeschaltet.
