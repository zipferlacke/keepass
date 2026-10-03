#!/usr/bin/env bash
# Durch alle vier Ansichten blättern: Einträge, TOTP, Sicherheitscheck,
# Einstellungen. Jede zeichnet sich einmal komplett.
set -euo pipefail
cd "$(dirname "$0")/../.."
tests/oberflaeche/lauf.sh "#wc-skip,#lock-pick,#lock-unlock,input[name=pw]:::egal,.dialog_submit,[data-view=passwords],[data-view=totp],#tile-grid .tile[data-view=security],[data-view=settings]" "${1:-}"
