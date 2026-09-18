#!/usr/bin/env bash
#
# Bauen, aufs Handy spielen, Protokoll mitlesen — in einem Befehl.
#
#   tools/android.sh              bauen, installieren, Protokoll
#   tools/android.sh bauen        nur bauen
#   tools/android.sh sauber       Gradle-Reste wegräumen und neu bauen
#   tools/android.sh install      nur installieren (letzter Build)
#   tools/android.sh log          nur das Protokoll mitlesen
#
# Voraussetzungen: Android Studio für aarch64 (SDK + NDK), adb aus Fedora
# (`sudo dnf install android-tools`), `cargo install tauri-cli --version "^2"`.
# Auf dem Handy: Entwickleroptionen, USB-Debugging, Rechner bestätigt.
#
# Die Fassung hier ist die **Debug**-Fassung: Sie signiert sich selbst und
# lässt sich sofort installieren. Ausgeliefert wird trotzdem, was GitHub
# Actions mit den offiziellen Google-Werkzeugen baut.

set -Eeuo pipefail

PROJEKT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
PAKET=de.wuefl.wkeepass
APK="$PROJEKT/src-tauri/gen/android/app/build/outputs/apk/universal/debug/app-universal-debug.apk"

export ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export NDK_HOME="${NDK_HOME:-$(ls -d "$ANDROID_HOME"/ndk/* 2>/dev/null | sort -V | tail -1)}"
export JAVA_HOME="${JAVA_HOME:-$HOME/.local/share/android-studio/jbr}"

# Hängt dasselbe Handy über mehrere Wege am Rechner (Kabel, adb tcpip,
# Wireless-Debugging), bricht adb mit „more than one device" ab. Deshalb
# einmal eines auswählen und für alle Aufrufe festhalten. Nur fürs
# Installieren und fürs Protokoll — bauen geht auch ohne Handy.
geraet_waehlen() {
  [[ -n "${ANDROID_SERIAL:-}" ]] && return 0

  local liste anzahl
  liste=$(adb devices | awk '$2 == "device" { print $1 }')
  anzahl=$(printf '%s\n' "$liste" | grep -c .)

  [[ "$anzahl" -eq 0 ]] && { echo "Kein Gerät verbunden — adb devices prüfen." >&2; exit 1; }
  export ANDROID_SERIAL="$(printf '%s\n' "$liste" | head -1)"
  [[ "$anzahl" -gt 1 ]] && echo "==> Mehrere Verbindungen, es gilt: $ANDROID_SERIAL"
  return 0
}

bauen() {
  cd "$PROJEKT/src-tauri"
  # Das Android-Projekt liegt unter gen/ und steht nicht im Repository.
  if [[ ! -d gen/android ]]; then
    echo "==> Android-Projekt anlegen"
    cargo tauri android init
    cp -r icons/android/. gen/android/app/src/main/res/
  fi
  # Kotlin-Klassen, Manifest-Block, Abhängigkeiten — siehe dort.
  python3 "$PROJEKT/tools/android-einbinden.py"
  echo "==> Bauen"
  # Ohne das wiegt allein die Rust-Bibliothek über 250 MB — reine
  # Fehlersuchsymbole, die auf dem Handy niemand liest. Über WLAN bricht die
  # Übertragung daran ab. Gilt nur hier, der Desktop-Build bleibt, wie er ist.
  CARGO_PROFILE_DEV_STRIP=debuginfo \
    cargo tauri android build --apk --debug --target aarch64
}

installieren() {
  geraet_waehlen
  [[ -f "$APK" ]] || { echo "Keine APK da — erst bauen." >&2; exit 1; }
  echo "==> Installieren"
  # Schlägt es an der Signatur fehl, liegt eine Fassung von GitHub drauf.
  if ! adb install -r "$APK"; then
    echo "==> Vorherige Fassung entfernen und erneut versuchen"
    adb uninstall "$PAKET" || true
    adb install "$APK"
  fi
}

protokoll() {
  geraet_waehlen
  echo "==> Protokoll (Abbruch mit Strg-C)"
  adb logcat -c
  adb shell monkey -p "$PAKET" -c android.intent.category.LAUNCHER 1 >/dev/null
  adb logcat | grep -iE "wkeepass|RustStdoutStderr|Tauri|AndroidRuntime"
}

case "${1:-alles}" in
  bauen) bauen ;;
  # Gradle packt die APK Schritt für Schritt neu und lässt dabei alte
  # Stände im Archiv liegen — nach einer stark geschrumpften Bibliothek war
  # die Datei fünfmal so groß wie ihr Inhalt. Dagegen hilft nur aufräumen.
  sauber) rm -rf "$PROJEKT/src-tauri/gen/android/app/build"; bauen ;;
  install) installieren ;;
  log) protokoll ;;
  alles) bauen; installieren; protokoll ;;
  *) echo "Unbekannt: $1 — bauen | install | log" >&2; exit 1 ;;
esac
