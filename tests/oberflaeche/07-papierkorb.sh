#!/usr/bin/env bash
# Einträge → der Papierkorb steht als eigener Block unter der Liste,
# zugeklappt; aufgeklappt zeigt er, wann jeder Eintrag endgültig weg ist.
set -euo pipefail
cd "$(dirname "$0")/../.."
tests/oberflaeche/lauf.sh "#wc-skip,#lock-pick,#lock-unlock,input[name=pw]:::egal,.dialog_submit,[data-view=passwords],?.recycle-bin,!.recycle-bin td[data-col=left],.recycle-bin summary,?.recycle-bin td[data-col=left],[data-empty-bin],?dialog[open]" "${1:-}" "${2:-1200}" "${3:-900}"
