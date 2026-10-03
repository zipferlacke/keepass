#!/usr/bin/env bash
# Einstellungen → Versionen → einen Stand öffnen → zurück zur Liste.
# Prüft den Weg durch beide Dialoge und dass „Zurück" wieder die Liste zeigt.
set -euo pipefail
cd "$(dirname "$0")/../.."
tests/oberflaeche/lauf.sh "#wc-skip,#lock-pick,#lock-unlock,input[name=pw]:::egal,.dialog_submit,[data-view=settings],#btn-versions,?.version-row,.version-row,?.version-change,.uD-bar-left,?.version-row" "${1:-}" "${2:-1200}" "${3:-900}"
