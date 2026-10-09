#!/usr/bin/env bash
# Aufdecken: Sichtbar gemacht steht ein echtes Textfeld da, nicht ein
# umgestelltes Passwortfeld — im Entsperr-Dialog und im Eintrag (Auge und
# „Neu erzeugen"). Prüft ui/aufdecken.js, ui/formular.js, dialogs/entry.js.
set -euo pipefail
cd "$(dirname "$0")/../.."
tests/oberflaeche/lauf.sh "#wc-skip,#lock-pick,#lock-unlock,?dialog[open] input[name=pw],dialog[open] .pw-eye,?dialog[open] input[data-klartext],!dialog[open] input[name=pw],dialog[open] input[data-klartext]:::geheim,.dialog_submit,?.tile[data-kind=files],#recent-list tr[data-id\$='000000000001'],?#fld-password,#dlg-reveal-pw,?#fld-password + input[data-klartext],!#fld-password,#dlg-reveal-pw,?#fld-password,#dlg-gen-pw,?#fld-password + input[data-klartext]" "${1:-}" "${2:-1200}" "${3:-900}"
