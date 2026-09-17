# Autofill für Android

Was auf dem Desktop die Browser-Erweiterung macht, macht auf Android das
Betriebssystem selbst: Es erkennt ein Anmeldefeld, fragt die eingetragenen
Passwortmanager, und zeigt deren Vorschläge über der Tastatur an. Der
Anschluss dafür heißt `AutofillService`.

Hier liegt unsere Seite dieses Anschlusses.

## Warum das nicht in Rust geht

Die Frage kam schon einmal auf, deshalb hier festgehalten.

Android ruft den Dienst nicht auf, weil wir ihn irgendwo anmelden — es
**erzeugt eine Instanz unserer Klasse** und ruft Methoden darauf. Die Klasse
muss also im Manifest stehen, von `android.service.autofill.AutofillService`
erben und zur Laufzeit als Java-Objekt existieren. Ein Rust-Symbol kann das
nicht sein.

Dazu kommt: Der Dienst läuft **ohne unsere App**. Kein Fenster, kein
Webview, oft nicht einmal ein laufender Prozess von uns — das System startet
ihn, während der Nutzer in einer fremden App steht. Alles, was der Webview
sonst erledigt, fehlt hier.

Rust bleibt trotzdem der Ort, an dem die Datenbank aufgeht. Kotlin ist die
Hülle, die Android verlangt, und ruft über JNI hinein (`rust/`).

## Was hier hineingehört

```
kotlin/de/wuefl/wkeepass/autofill/
    WKeePassAutofillService.kt   Der Dienst: onFillRequest, onSaveRequest
    FeldFinder.kt                Den ViewNode-Baum nach Anmeldefeldern absuchen
    AusfuellActivity.kt          Entsperren und Auswählen — fehlt noch

res/xml/
    autofill_service.xml         Verweis auf die Einstellungen des Dienstes

manifest.xml                     Der <service>-Block fürs AndroidManifest
```

Die Rust-Seite liegt **nicht** hier, sondern als Modul unter
`src-tauri/src/`, so wie `keepass_extension` es vormacht. Sie ist Teil des
Kerns und wird mit ihm übersetzt; dieser Ordner enthält nur, was Android
selbst verlangt.

Passkeys sind **nicht** Teil davon. Dafür gibt es seit Android 14 einen
eigenen Anschluss, `CredentialProviderService`. Gleiches Muster, andere
Klasse — der bekommt einen Nachbarordner, wenn es soweit ist.

## Wie das in die App kommt

Tauri erzeugt das Android-Projekt unter `src-tauri/gen/android`. Diese
Dateien werden dorthin kopiert, nicht dort bearbeitet — `gen/` heißt, was es
heißt, und wird bei Bedarf neu erzeugt.

```bash
cd src-tauri
cargo tauri android init      # erzeugt gen/android
```

Danach:

* `kotlin/` nach `gen/android/app/src/main/java/`
* `res/` nach `gen/android/app/src/main/res/`
* den `<service>`-Block aus `manifest.xml` in
  `gen/android/app/src/main/AndroidManifest.xml`

Ein Skript dafür gehört nach `tools/`, sobald das Projekt einmal steht.

## Was fehlt

**Die Werkzeugkette ist auf diesem Rechner nicht da.** Weder JDK noch
Android-SDK noch NDK, und `rustup` kennt kein `aarch64-linux-android`. Ohne
das lässt sich hier nichts übersetzen und erst recht nichts ausprobieren —
was in diesem Ordner liegt, ist bis dahin ungeprüft.

```bash
sudo dnf install java-21-openjdk-devel
rustup target add aarch64-linux-android armv7-linux-androideabi \
                  i686-linux-android x86_64-linux-android
# SDK und NDK über Android Studio oder das commandline-tools-Paket,
# danach ANDROID_HOME und NDK_HOME setzen.
```

**Zwei inhaltliche Lücken**, die schwerer wiegen als die Werkzeuge:

*Die Datei.* Auf Android liegt die kdbx-Datei hinter `content://`, nicht
hinter einem Pfad. Der Kern arbeitet durchgehend mit `std::path::Path` und
`std::fs`. Das ist keine Kleinigkeit — entweder eine dauerhafte Freigabe
über `takePersistableUriPermission` und Lesen über den `ContentResolver`,
oder eine Kopie im privaten Verzeichnis der App samt Rückschreiben.

*Der Schlüsselspeicher.* `seal.rs` legt das App-Geheimnis in den
Secret Service über D-Bus. Den gibt es auf Android nicht; dort ist es der
Android Keystore, und der bindet die Herausgabe an die biometrische Prüfung
— genau das, was auf dieser Seite ohnehin gebraucht wird.

## Die Zuordnung: welcher Eintrag zu welcher App?

Auf dem Desktop ist es eine Adresse. Hier ist es ein Paketname wie
`com.nextcloud.client`, und dazu passt keine URL.

Der eingeführte Weg ist `androidapp://com.nextcloud.client` als zusätzliche
URL am Eintrag — KeePassDX und Keepass2Android machen es so, und unsere
Adressensuche kennt bereits mehrere URLs je Eintrag
(`KP_ADDITIONAL_URL_*`). Für Browser-Apps liefert Android zusätzlich die
Webadresse mit; dann greift dieselbe Logik wie auf dem Desktop.

Was **nicht** genügt: den Paketnamen allein glauben. Er lässt sich
nachbauen. Google veröffentlicht dafür Digital Asset Links; ohne diese
Prüfung bleibt der Paketname ein Hinweis, keine Kennung.
