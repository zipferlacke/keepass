#!/usr/bin/env bash
#
# Lädt eine Seite im Browser ohne Fenster und gibt deren Konsole als Text
# aus. Zurück kommt 1, sobald eine Zeile mit ERROR dabei war.
#
#   tests/lib/lauf.sh <pfad-ab-projektwurzel> <wartesekunden> [bild.png] [breite] [hoehe]
#
# Firefox braucht ein Ziel zum Knipsen, sonst beendet es sich nie — das
# Bild entsteht also immer, es landet nur im Papierkorb, wenn keines
# gewünscht ist.
set -euo pipefail
wurzel="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$wurzel"

seite="${1:?Seite angeben}"
warten="${2:-5}"
bild="${3:-}"
breite="${4:-1200}"
hoehe="${5:-900}"
port="${PORT:-8749}"

profil="$(mktemp -d)"
protokoll="$(mktemp)"
knipsziel="${bild:-$(mktemp -u --suffix=.png)}"

# Ein Server aus einem abgebrochenen Lauf hält den Port sonst fest.
pkill -f "server[.]py $port" 2>/dev/null || true

python3 tests/lib/server.py "$port" "$warten" >"$protokoll" 2>&1 &
server=$!
trap 'kill $server 2>/dev/null || true; rm -rf "$profil"; rm -f "$protokoll"; [ -n "$bild" ] || rm -f "$knipsziel"' EXIT

# Warten, bis der Server steht
for _ in $(seq 1 30); do
  curl -sf "http://localhost:$port/" >/dev/null 2>&1 && break
  sleep 0.2
done

firefox --headless --profile "$profil" --screenshot "$knipsziel" \
        --window-size="$breite,$hoehe" "http://localhost:$port/$seite" >/dev/null 2>&1 || true

sleep 0.5
cat "$protokoll"
[ -n "$bild" ] && echo "Bild: $bild"

! grep -q '^ERROR' "$protokoll"
