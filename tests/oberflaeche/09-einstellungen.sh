#!/usr/bin/env bash
# Einstellungen: die Abschnitte stehen, „Papierkorb leeren" fragt nach und
# lässt sich abbrechen. Prüft pages/settings.js und pages/lock.js (PIN-Knöpfe).
set -euo pipefail
cd "$(dirname "$0")/../.."
tests/oberflaeche/lauf.sh "#wc-skip,#lock-pick,#lock-unlock,input[name=pw]:::egal,.dialog_submit,[data-view=settings],?#btn-versions,?#db-level,?#btn-export,?#btn-empty-bin,#btn-empty-bin,?dialog[open],.dialog_close,!dialog[open]" "${1:-}" "${2:-1200}" "${3:-900}"
