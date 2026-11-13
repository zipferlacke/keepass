#!/usr/bin/env bash
# Der Regler für die Verschlüsselungsstärke wählt nur aus. Geschrieben
# wird erst mit „Übernehmen": Beim Verschieben geht kein Dialog auf, der
# Knopf erscheint, und „Zurück" stellt den Stand wieder her.
set -euo pipefail
cd "$(dirname "$0")/../.."
tests/oberflaeche/lauf.sh "#wc-skip,#online-ok,#lock-pick,#lock-unlock,input[name=pw]:::egal,.dialog_submit,[data-view=settings],?#db-level,!#db-level-ok,#db-level:::0,?#db-level-ok,!dialog[open],#db-level-undo,!#db-level-ok,#db-level:::0,#db-level-ok,!#db-level-ok" "${1:-}"
