#!/usr/bin/env bash
# Ein neuer Ordner steht sofort im Baum — auch ohne Eintrag darin
# (Platzhalterzeile, t-placeholder in tableview). Prüft pages/entries.js.
set -euo pipefail
cd "$(dirname "$0")/../.."
tests/oberflaeche/lauf.sh "#wc-skip,#lock-pick,#lock-unlock,input[name=pw]:::egal,.dialog_submit,.tile[data-view=passwords]:not([data-kind]),#btn-add,[data-choice=folder],dialog[open] input[name=name]:::Leerer Ordner,dialog[open] .dialog_submit,?#entry-table tr.tv-group-row[data-folder='Leerer Ordner']" "${1:-}" "${2:-1200}" "${3:-900}"
