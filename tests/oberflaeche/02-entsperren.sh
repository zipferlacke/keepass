#!/usr/bin/env bash
# Willkommen überspringen, Demo-Datenbank wählen, mit Master-Passwort
# entsperren — danach steht die Übersicht mit den Einträgen. Der Dialog
# setzt den Fokus gleich ins Passwortfeld (lostippen ohne Klick).
set -euo pipefail
cd "$(dirname "$0")/../.."
tests/oberflaeche/lauf.sh "#wc-skip,#lock-pick,#lock-unlock,?dialog[open] input[name=pw]:focus,input[name=pw]:::egal,.dialog_submit" "${1:-}"
