#!/usr/bin/env bash
# Konflikte: Nach dem Entsperren zeigt der Dialog die Beispielkonflikte der
# Demo. Ein Passwort lässt sich je Seite aufdecken, je Feld ist eine Seite
# gewählt, und „Auswahl übernehmen" entscheidet den Konflikt. Prüft
# dialogs/konflikte.js.
set -euo pipefail
cd "$(dirname "$0")/../.."
ZUSATZ='?konflikte' tests/oberflaeche/lauf.sh "#wc-skip,#online-ok,#lock-pick,#lock-unlock,input[name=pw]:::egal,.dialog_submit,?.konflikt[data-konflikt=demo-ordner],?.konflikt-feld[data-feld='feld:Password'] input[value=extern]:checked,.konflikt-auge[data-zeigen=hier],?.konflikt-auge[data-offen],[data-konflikt=demo-ordner] input[value=extern],[data-konflikt=demo-ordner] [data-wahl=felder],?[data-konflikt=demo-ordner].entschieden" "${1:-}" "${2:-1200}" "${3:-900}"
