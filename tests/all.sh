#!/usr/bin/env bash
#
# Alles prüfen: Kern, Module, Oberfläche.
#
#   tests/all.sh           alles
#   tests/all.sh --ohne-rust   nur der Browser-Teil (schnell)
#
# Jeder Teil lässt sich auch einzeln aufrufen:
#   tests/rust.sh
#   tests/einheit/lauf.sh [name]
#   tests/oberflaeche/<datei>.sh
set -uo pipefail
cd "$(dirname "$0")/.."

gut=0
schlecht=0
namen_schlecht=()

lauf() {
  local name="$1"; shift
  echo
  echo "=== $name"
  if "$@"; then
    gut=$((gut + 1))
  else
    schlecht=$((schlecht + 1))
    namen_schlecht+=("$name")
  fi
}

[ "${1:-}" = "--ohne-rust" ] || lauf "Kern (cargo test)" tests/rust.sh
lauf "Module" tests/einheit/lauf.sh

for f in tests/oberflaeche/*.sh; do
  [ -e "$f" ] || continue
  [ "$(basename "$f")" = "lauf.sh" ] && continue
  lauf "Oberfläche: $(basename "$f" .sh)" "$f"
done

echo
echo "================================"
echo "gut: $gut   schlecht: $schlecht"
[ $schlecht -eq 0 ] || printf 'gescheitert: %s\n' "${namen_schlecht[*]}"
exit $(( schlecht > 0 ? 1 : 0 ))
