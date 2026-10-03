#!/usr/bin/env python3
"""Setzt unsere Android-Teile in das von Tauri erzeugte Projekt ein.

`src-tauri/gen/android` ist Wegwerfware: Tauri erzeugt es neu, und es steht
nicht im Repository. Was Android über Tauri hinaus verlangt, liegt deshalb
unter `keepass-android/` und kommt bei jedem Bauen hier hinein:

  appdata/icons/android/  → app/src/main/res/ (App-Symbol, bei jedem Bauen)
  kotlin/                 → app/src/main/java/
  res/                    → app/src/main/res/
  proguard-wkeepass.pro   → app/
  manifest.xml            → in <application> von AndroidManifest.xml
  Name der Debug-Fassung  → app/src/debug/res/values/strings.xml: „WKeePass-Debug"
  Kamera-Berechtigung     → vor <application>
  androidx.credentials    → als Abhängigkeit in app/build.gradle.kts
  Upload-Signatur         → app/build.gradle.kts, wenn es die Schlüsseldatei
                            gibt (.secrets/wkeepass.properties bzw.
                            $ANDROID_SIGNING – setzt `tauri-android keepass
                            release`). Sie nennt storeFile, storePassword,
                            keyAlias, keyPassword. `.secrets/` steht in
                            .gitignore. In der GitHub-Aktion gibt es die Datei
                            nicht – dort wird nach dem Bauen signiert.

Mehrfach aufrufbar: Der Manifest-Block und die Signatur stehen zwischen
Markierungen und werden ersetzt, die Abhängigkeit nur einmal eingetragen.

Aufgerufen von tools/android.sh und der GitHub-Aktion.
"""

import os
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
    # Früher nur beim Anlegen des Projekts kopiert — ein geändertes Symbol
    # kam dann nie auf dem Handy an.
    shutil.copytree(PROJEKT / "appdata/icons/android", APP / "src/main/res", dirs_exist_ok=True)
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


SIGNATUR = Path(os.environ.get("ANDROID_SIGNING", PROJEKT / ".secrets/wkeepass.properties"))
SIG_ANFANG, SIG_ENDE = "// wkeepass:signatur-anfang", "// wkeepass:signatur-ende"


def signatur() -> None:
    """Release-Signatur in app/build.gradle.kts eintragen (bzw. erneuern).

    Ohne Schlüsseldatei verschwinden nur alte Einträge – die Release-Fassung
    bleibt dann unsigniert, wie Tauri sie baut.
    """
    datei = APP / "build.gradle.kts"
    text = datei.read_text(encoding="utf-8")
    # Alte Einträge weg – so bleibt das Skript beliebig oft aufrufbar
    text = re.sub(r"[ \t]*" + re.escape(SIG_ANFANG) + r".*?" + re.escape(SIG_ENDE) + r"\n?", "", text, flags=re.S)
    if not SIGNATUR.is_file():
        datei.write_text(text, encoding="utf-8")
        return
    laden = (f"{SIG_ANFANG}\nval wkeepassSigning = Properties().apply {{\n"
             f"    val f = file(\"{SIGNATUR}\")\n    if (f.exists()) f.inputStream().use {{ load(it) }}\n}}\n{SIG_ENDE}\n")
    konfig = (f"    {SIG_ANFANG}\n    signingConfigs {{\n"
              "        if (wkeepassSigning.getProperty(\"storeFile\") != null) create(\"upload\") {\n"
              "            storeFile = file(wkeepassSigning.getProperty(\"storeFile\"))\n"
              "            storePassword = wkeepassSigning.getProperty(\"storePassword\")\n"
              "            keyAlias = wkeepassSigning.getProperty(\"keyAlias\")\n"
              "            keyPassword = wkeepassSigning.getProperty(\"keyPassword\")\n"
              "        }\n    }\n"
              f"    {SIG_ENDE}\n")
    nutzen = (f"            {SIG_ANFANG}\n"
              "            signingConfigs.findByName(\"upload\")?.let { signingConfig = it }\n"
              f"            {SIG_ENDE}\n")
    text = text.replace("android {\n", laden + "android {\n" + konfig, 1)
    text = text.replace('getByName("release") {\n', 'getByName("release") {\n' + nutzen, 1)
    datei.write_text(text, encoding="utf-8")


DEBUG_NAME = "WKeePass-Debug"


def debug_name() -> None:
    """Die Debug-Fassung heißt anders.

    Sie liegt neben der echten App (``debugApplicationIdSuffix`` in
    tauri.conf.json) — hießen beide „WKeePass", wüsste man im Starter und im
    Autofill-Dienst nicht, welche man gerade vor sich hat. Ressourcen unter
    ``src/debug`` gelten nur für diese Fassung.
    """
    ziel = APP / "src/debug/res/values"
    ziel.mkdir(parents=True, exist_ok=True)
    (ziel / "strings.xml").write_text(
        "<resources>\n"
        f'    <string name="app_name">"{DEBUG_NAME}"</string>\n'
        f'    <string name="main_activity_title">"{DEBUG_NAME}"</string>\n'
        "</resources>\n", encoding="utf-8")


def main() -> int:
    if not APP.is_dir():
        print(f"{APP} fehlt — erst `cargo tauri android init`.", file=sys.stderr)
        return 1
    kopieren()
    manifest()
    berechtigungen()
    gradle()
    signatur()
    debug_name()
    print("==> Android-Teile eingesetzt" + (" (mit Upload-Signatur)" if SIGNATUR.is_file() else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
