#!/usr/bin/env bash
# „+" → Neu anlegen: die Auswahl, dann „Ordner anlegen" (Dialog mit Eingabe),
# danach „Importieren" (schließt die Auswahl; die Dateiauswahl des Systems lässt sich hier nicht prüfen). Prüft dialogs/create.js.
set -euo pipefail
cd "$(dirname "$0")/../.."
tests/oberflaeche/lauf.sh "#wc-skip,#lock-pick,#lock-unlock,input[name=pw]:::egal,.dialog_submit,#btn-add,?[data-choice=manual],[data-choice=folder],?dialog[open] input,.dialog_close,!dialog[open],#btn-add,[data-choice=import],!dialog[open]" "${1:-}" "${2:-1200}" "${3:-900}"
