# WKeePass

Passwortverwaltung für KeePass-Datenbanken (KDBX) — für Linux, Windows,
macOS und Android. Öffnet und schreibt dieselben Dateien wie KeePassXC und
KeePassDX, gleicht Änderungen anderer Geräte über die Cloud ab, kann
2FA-Codes, Passkeys, Autofill und den Browser.

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
*Einstellungen → Datenbank → Versionen* zeigt ein Stand, was sich seitdem geändert hat; zurückholen lässt
sich ein einzelner Eintrag oder alles.

## Tests

```
tests/all.sh                    alles: Kern, Module, Oberfläche
tests/all.sh --ohne-rust        nur der Browser-Teil
tests/rust.sh [name]            Tests des Kerns (cargo test)
tests/einheit/lauf.sh [name]    Modultests im Browser, eine Datei je Modul
tests/oberflaeche/02-entsperren.sh   eine Klickfolge durch die Demo
```

Die Browser-Tests starten die Oberfläche ohne Tauri; die Antworten kommen aus `js/data/demo.js`. Die
Konsole der Seite kommt als Text heraus, ein Fehler macht den Lauf rot.

## Lizenz

Apache License 2.0 — siehe [LICENSE](LICENSE) und [NOTICE](NOTICE).

Du darfst WKeePass frei nutzen, verändern und weitergeben, auch
kommerziell.

## Spende

Nutzt du WKeePass kommerziell oder baust es in ein kommerzielles Produkt
ein, freue ich mich über eine kleine Spende. Das ist eine Bitte, keine
Bedingung der Lizenz.
