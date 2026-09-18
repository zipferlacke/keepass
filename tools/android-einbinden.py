#!/usr/bin/env python3
"""Setzt unsere Android-Teile in das von Tauri erzeugte Projekt ein.

`src-tauri/gen/android` ist Wegwerfware: Tauri erzeugt es neu, und es steht
nicht im Repository. Was Android über Tauri hinaus verlangt, liegt deshalb
unter `keepass-android/` und kommt bei jedem Bauen hier hinein:

  kotlin/                 → app/src/main/java/
  res/                    → app/src/main/res/
  proguard-wkeepass.pro   → app/
  manifest.xml            → in <application> von AndroidManifest.xml
  Kamera-Berechtigung     → vor <application>
  androidx.credentials    → als Abhängigkeit in app/build.gradle.kts

Mehrfach aufrufbar: Der Manifest-Block steht zwischen Markierungen und wird
ersetzt, die Abhängigkeit nur einmal eingetragen.

Aufgerufen von tools/android.sh und der GitHub-Aktion.
"""

import re
import shutil
import sys
from pathlib import Path

PROJEKT = Path(__file__).resolve().parent.parent
QUELLE = PROJEKT / "keepass-android"
APP = PROJEKT / "src-tauri/gen/android/app"

ANFANG = "<!-- wkeepass:anfang -->"
ENDE = "<!-- wkeepass:ende -->"

# Passkeys über den Credential Manager. Die Klassen für Anbieter stecken im
# Hauptpaket; die Fassung muss Android 14 kennen (ab 1.2).
ABHAENGIGKEIT = 'implementation("androidx.credentials:credentials:1.5.0")'

# Berechtigungen außerhalb von <application>. Die Kamera für den QR-Scanner
# (TOTP einrichten): Den Webview fragt Tauri selbst um Erlaubnis, aber nur
# für Berechtigungen, die im Manifest stehen — sonst hieß es sofort
# „Berechtigung fehlt". `required="false"`: Ohne Kamera läuft die App auch.
BERECHTIGUNGEN = [
    '<uses-permission android:name="android.permission.CAMERA" />',
    '<uses-feature android:name="android.hardware.camera" android:required="false" />',
]


def kopieren() -> None:
    shutil.copytree(QUELLE / "kotlin", APP / "src/main/java", dirs_exist_ok=True)
    shutil.copytree(QUELLE / "res", APP / "src/main/res", dirs_exist_ok=True)
    shutil.copy2(QUELLE / "proguard-wkeepass.pro", APP / "proguard-wkeepass.pro")


def manifest() -> None:
    datei = APP / "src/main/AndroidManifest.xml"
    text = datei.read_text(encoding="utf-8")

    block = (QUELLE / "manifest.xml").read_text(encoding="utf-8")
    # Der erste Kommentar erklärt nur die Datei selbst — der gehört nicht
    # ins Manifest.
    block = re.sub(r"^\s*<!--.*?-->\s*", "", block, count=1, flags=re.S)
    einsatz = f"{ANFANG}\n{block.strip()}\n        {ENDE}\n"

    if ANFANG in text:
        text = re.sub(re.escape(ANFANG) + r".*?" + re.escape(ENDE) + r"\n?", einsatz, text, flags=re.S)
    else:
        text = text.replace("</application>", f"    {einsatz}    </application>", 1)
    datei.write_text(text, encoding="utf-8")


def berechtigungen() -> None:
    datei = APP / "src/main/AndroidManifest.xml"
    text = datei.read_text(encoding="utf-8")
    fehlend = [b for b in BERECHTIGUNGEN if b not in text]
    if fehlend:
        zeilen = "".join(f"    {b}\n" for b in fehlend)
        text = text.replace("    <application", zeilen + "\n    <application", 1)
        datei.write_text(text, encoding="utf-8")


def gradle() -> None:
    datei = APP / "build.gradle.kts"
    text = datei.read_text(encoding="utf-8")
    if ABHAENGIGKEIT in text:
        return
    text = text.replace("dependencies {", f"dependencies {{\n    {ABHAENGIGKEIT}", 1)
    datei.write_text(text, encoding="utf-8")


def main() -> int:
    if not APP.is_dir():
        print(f"{APP} fehlt — erst `cargo tauri android init`.", file=sys.stderr)
        return 1
    kopieren()
    manifest()
    berechtigungen()
    gradle()
    print("==> Android-Teile eingesetzt")
    return 0


if __name__ == "__main__":
    sys.exit(main())
