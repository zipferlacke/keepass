#!/usr/bin/env bash
# PIN und Freigabe: „Festlegen …" und „Bequem entsperren → Wählen …" öffnen
# ihren Dialog. Prüft pages/lock.js und ui/formular.js (Hinweis zur PIN).
set -euo pipefail
cd "$(dirname "$0")/../.."
tests/oberflaeche/lauf.sh "#wc-skip,#lock-pick,#lock-unlock,input[name=pw]:::egal,.dialog_submit,[data-view=settings],#btn-pin-create,?dialog[open],.dialog_close,!dialog[open],#btn-access,?dialog[open],.dialog_close" "${1:-}" "${2:-1200}" "${3:-900}"
