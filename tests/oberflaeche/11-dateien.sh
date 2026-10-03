#!/usr/bin/env bash
# Dateien: die Seite zeichnet, ein Ordner klappt auf, eine Datei öffnet die
# Vorschau. Prüft pages/entries.js (renderFiles) und dialogs/entry.js.
set -euo pipefail
cd "$(dirname "$0")/../.."
tests/oberflaeche/lauf.sh "#wc-skip,#lock-pick,#lock-unlock,input[name=pw]:::egal,.dialog_submit,.tile[data-kind=files],?#entry-table tr.tv-group-row[data-folder='Privat'],#entry-table tr.tv-group-row[data-folder='Privat'] .tv-group-content,?#entry-table [data-file-info],#entry-table tr.tv-group-row:has([data-file-info$='000000000013']) .tv-group-content,#entry-table tr[data-file-name='Mietvertrag.md'] td[data-col=name],?dialog#file-viewer[open]" "${1:-}" "${2:-1200}" "${3:-900}"
