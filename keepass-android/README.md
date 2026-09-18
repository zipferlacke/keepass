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

## Was hier liegt

```
kotlin/de/wuefl/wkeepass/
    kern/Kern.kt                 Tür zum Rust-Kern (src-tauri/src/android_services.rs)
    autofill/
        WKeePassAutofillService  onFillRequest, onSaveRequest
        FeldFinder               Anmeldefelder im ViewNode-Baum finden
        AusfuellActivity         Auswahl, Einsetzen, App merken
    passkey/
        WKeePassCredentialService  Vorschläge an den Credential Manager
        PasskeyActivity            Ausweis, Signieren, Anlegen
    sicherheit/
        Geraeteschluessel        Keystore-Schlüssel, nur per Biometrie frei
        Bestaetigung             „Bist du es?" vor einem Passkey

res/xml/                         Selbstauskunft von Autofill und Passkey-Anbieter
manifest.xml                     Dienste und Activities fürs AndroidManifest
proguard-wkeepass.pro            Schutz der JNI-Klassen vor dem Optimierer
```

Rust bleibt der Ort, an dem die Datenbank aufgeht. Kotlin ist die Hülle,
die Android verlangt: Dienste, Activities und Rückrufe lassen sich nur als
Java-Klassen anbieten.

## Wie es abläuft

**Autofill.** Bei offener Datenbank zeigt der Dienst je passendem Konto
eine Zeile mit dessen Namen, darunter „Anderen Eintrag wählen …". Die
fremde App sieht dabei kein Passwort: Jede Zeile trägt nur eine
Authentifizierung, die Werte entstehen erst beim Antippen in der
`AusfuellActivity`. Wer über die Liste einen noch nicht passenden Eintrag
wählt, hängt ihm die App (`androidapp://<paket>`) bzw. Seite an.

Einmalcodes: Hat das Formular ein Code-Feld, geht der TOTP-Code dort
hinein. Sonst landet er nach dem Einsetzen für 30 Sekunden in der
Zwischenablage — für die nächste Seite.

Nach dem Absenden eines Formulars bietet Android an, das Eingetippte zu
speichern. Gibt es für Seite und Benutzernamen schon einen Eintrag, bekommt
der das neue Passwort; sonst entsteht ein neuer. Ist WKeePass gerade
gesperrt, wird der Zugang im Arbeitsspeicher vorgemerkt und beim nächsten
Entsperren eingetragen.

**Passkeys** (ab Android 14). Der Dienst meldet die Passkeys der
Gegenstelle; die Signatur entsteht erst in der `PasskeyActivity`, nach
Finger oder Displaysperre. Gespeichert wird in denselben Feldern wie bei
KeePassXC — Desktop und Handy sehen dieselben Passkeys.

**Gesperrt?** Dann holen beide die App nach vorn. Entsperrt wird dort, auf
den bekannten Wegen; danach das Feld erneut antippen. Ein zweiter
Entsperrweg im Dienst wäre eine zweite Tür, die man genauso sichern müsste.

**Einschalten** auf dem Handy: Einstellungen → Passwörter, Passkeys und
Konten → WKeePass als bevorzugten Dienst wählen.

## Wie das in die App kommt

Tauri erzeugt das Android-Projekt unter `src-tauri/gen/android`; `gen/`
wird nie von Hand bearbeitet. `tools/android-einbinden.py` kopiert bei
jedem Bauen Kotlin, Ressourcen und ProGuard-Regel hinein, setzt den Block
aus `manifest.xml` ins Manifest und trägt `androidx.credentials` als
Abhängigkeit ein. `tools/android.sh` und die GitHub-Aktion rufen es auf.

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
