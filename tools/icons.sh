#!/usr/bin/env bash
# Legt die Web-Icons aus dem App-Symbol an.
#
# Alle Bilder liegen in appdata/, die App-Symbole in appdata/icons/ (dort
# auch android/ und ios/). Neu erzeugen lassen sie sich aus einer Vorlage mit
#   cargo tauri icon vorlage.png -o appdata/icons
# icon.png hat 512 px — größer geht nur mit einer Vorlage in höherer
# Auflösung, hochrechnen würde unscharf.
set -euo pipefail
cd "$(dirname "$0")/.."

for groesse in 144 192 512; do
  magick appdata/icons/icon.png -resize "${groesse}x${groesse}" "appdata/wkeepass-$groesse.png"
done
echo "Web-Icons in appdata/ angelegt."
