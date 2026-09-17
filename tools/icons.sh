#!/usr/bin/env bash
# Kopiert die App-Icons nach appdata/ und legt die Web-Icons der Vorlage an.
# icon.png hat 512 px — größer geht nur mit einer Vorlage in höherer
# Auflösung, hochrechnen würde unscharf.
set -euo pipefail
cd "$(dirname "$0")/.."

rm -rf appdata/icons
cp -r src-tauri/icons appdata/icons
for groesse in 144 192 512; do
  magick src-tauri/icons/icon.png -resize "${groesse}x${groesse}" "appdata/wkeepass-$groesse.png"
done
echo "Icons nach appdata/ kopiert."
