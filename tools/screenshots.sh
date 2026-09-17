#!/usr/bin/env bash
#
# Screenshots für die Landingpage.
#
# Du gibst unten nur Elemente an. Jedes wird in beiden Formaten aufgenommen,
# einmal Laptop und einmal Handy.
#
#   ./tools/screenshots.sh
#
# Voraussetzungen:
#   npm install -g tauri-agent-tools      (braucht Node 20 oder neuer)
#   cargo tauri dev --features agent      (die Brücke hängt an diesem Feature)
#
# Die App muss laufen und mit der Demo-Datenbank entsperrt sein — im Browser
# ohne Rust reicht ein leeres Passwort.

set -euo pipefail

CLI=${CLI:-tauri-agent-tools}
OUT=${OUT:-appdata/screenshots}
WINDOW=${WINDOW:-WKeePass}

# ---------------------------------------------------------------------------
# Hier eintragen, was aufgenommen werden soll:  "name:ansicht:css-selektor"
#
#   name       Dateiname ohne Endung
#   ansicht    welche Seite vorher geöffnet wird (home, passwords, totp,
#              security, settings) — oder "-", wenn die aktuelle bleiben soll
#   selektor   was genau aufgenommen wird
# ---------------------------------------------------------------------------
SHOTS=(
  "start:home:#view-home"
  "passwoerter:passwords:#view-passwords"
  "totp:totp:#view-totp"
  "totp-einzeln:totp:.totp-card"
  "sicherheit:security:#view-security"
  "einstellungen:settings:#view-settings"
)

# Zielformate: name breite höhe
FORMATS=(
  "laptop 1440 900"
  "handy 390 844"
)

# ---------------------------------------------------------------------------

command -v "$CLI" >/dev/null || {
  echo "»$CLI« nicht gefunden. Installieren mit:  npm install -g tauri-agent-tools" >&2
  exit 1
}

mkdir -p "$OUT"

for format in "${FORMATS[@]}"; do
  read -r label width height <<<"$format"
  echo "── $label (${width}×${height})"

  # Fenster auf das Zielformat bringen. Der Webview rechnet die
  # Mediendefinitionen daraufhin neu — deshalb kurz warten.
  "$CLI" eval --window "$WINDOW" \
    "window.resizeTo($width, $height)" >/dev/null
  sleep 0.6

  for shot in "${SHOTS[@]}"; do
    IFS=: read -r name view selector <<<"$shot"

    if [ "$view" != "-" ]; then
      # showView ist die Umschaltung der Oberfläche (siehe src-ui/js/app.js).
      "$CLI" eval --window "$WINDOW" "showView('$view')" >/dev/null
      sleep 0.4
    fi

    "$CLI" screenshot \
      --window "$WINDOW" \
      --selector "$selector" \
      --output "$OUT/${name}-${label}.png" \
      --format png

    echo "   $OUT/${name}-${label}.png"
  done
done

echo
echo "Fertig. $(( ${#SHOTS[@]} * ${#FORMATS[@]} )) Bilder in $OUT"
