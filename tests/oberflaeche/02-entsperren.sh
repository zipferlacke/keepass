#!/usr/bin/env bash
# Willkommen überspringen, Demo-Datenbank wählen, mit Master-Passwort
# entsperren — danach steht die Übersicht mit den Einträgen.
set -euo pipefail
cd "$(dirname "$0")/../.."
tests/oberflaeche/lauf.sh "#wc-skip,#lock-pick,#lock-unlock,input[name=pw]:::egal,.dialog_submit" "${1:-}"
