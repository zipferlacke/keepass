#!/usr/bin/env bash
# Tastatur: Strg+F zur Suche, Pfeile durch die Liste, Enter klappt den Ordner
# auf, Strg+X/Esc/Strg+V schneiden aus, verwerfen und fügen ein, Tippen sucht,
# Strg+N legt an. Prüft pages/tasten.js und das Ausschneiden in pages/entries.js.
set -euo pipefail
cd "$(dirname "$0")/../.."
tests/oberflaeche/lauf.sh "#wc-skip,#lock-pick,#lock-unlock,input[name=pw]:::egal,.dialog_submit,^ctrl+f,?#view-passwords[data-active],?#search:focus,^ArrowDown,?#entry-table tr[data-current].tv-group-row,!#search:focus,^Enter,?#entry-table tr[data-id],^ArrowDown,?#entry-table tr[data-current][data-id],^ctrl+x,?#entry-table tr[data-cut],^Escape,!#entry-table tr[data-cut],^ctrl+x,?#entry-table tr[data-cut],^ArrowUp,^shift+Enter,^ArrowDown,?#entry-table tr[data-current].tv-group-row,^ctrl+v,!#entry-table tr[data-cut],^k,?#search:focus,^Escape,^ctrl+n,?dialog.userDialog[open]" "${1:-}" "${2:-1200}" "${3:-900}"
