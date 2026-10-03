#!/usr/bin/env bash
#
# Die Tests des Kerns. Dauert beim ersten Mal, danach geht es schnell.
#
#   tests/rust.sh            alle
#   tests/rust.sh versions   nur was zum Namen passt
set -euo pipefail
cd "$(dirname "$0")/../src-tauri"
cargo test --quiet ${1:+"$1"}
