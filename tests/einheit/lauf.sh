#!/usr/bin/env bash
#
# Modultests im echten Browser — dort laufen die Module so, wie sie auch
# in der App laufen (ES-Module, DOM, fetch).
#
#   tests/einheit/lauf.sh                     alle Tests
#   tests/einheit/lauf.sh core-entries        nur diesen
#
# Jede Datei `tests/einheit/<name>.test.js` meldet sich selbst; die
# Bilanz steht am Ende. Ein Fehlschlag macht den Aufruf rot.
set -euo pipefail
wurzel="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$wurzel"

auswahl="${1:-}"
dateien=()
for f in tests/einheit/*.test.js; do
  [ -e "$f" ] || continue
  name="$(basename "$f" .test.js)"
  if [ -z "$auswahl" ] || [ "$auswahl" = "$name" ]; then
    dateien+=("$name")
  fi
done

if [ ${#dateien[@]} -eq 0 ]; then
  echo "Keine Modultests gefunden: $auswahl"
  exit 1
fi

# Eine Seite, die alle gewählten Testdateien lädt.
{
  echo '<!doctype html><html lang="de"><head><meta charset="utf-8"><title>Modultests</title></head><body>'
  echo '<script type="module">'
  echo "import { fangeAlles, melde } from '/tests/lib/melden.js';"
  echo 'fangeAlles();'
  for name in "${dateien[@]}"; do
    echo "await import('/tests/einheit/$name.test.js');"
  done
  echo "import { bericht } from '/tests/lib/pruef.js';"
  echo 'await bericht();'
  echo '</script></body></html>'
} > tests/_einheit.html
trap 'rm -f tests/_einheit.html' EXIT

echo "Modultests: ${dateien[*]}"
tests/lib/lauf.sh tests/_einheit.html 4
