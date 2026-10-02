#!/usr/bin/env bash
# Die App startet und zeigt die Willkommensseite — ohne einen Mucks in der Konsole.
set -euo pipefail
cd "$(dirname "$0")/../.."
tests/oberflaeche/lauf.sh "" "${1:-}"
