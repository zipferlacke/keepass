#!/usr/bin/env bash
# Einen Eintrag öffnen, den Dialog ansehen und wieder abbrechen.
# Prüft den Weg durch dialogs/entry.js samt Anhängen und Einmalcode.
set -euo pipefail
cd "$(dirname "$0")/../.."
tests/oberflaeche/lauf.sh "#wc-skip,#lock-pick,#lock-unlock,input[name=pw]:::egal,.dialog_submit,[data-view=passwords],table tbody tr[data-id],.dialog_close" "${1:-}"
