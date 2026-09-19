#!/usr/bin/env bash
#
# Legt die Oberfläche als Demo zum Ausprobieren im Netz ab.
#
#   ./tools/demo-web.sh ../../wuefl/wkeepass/demo
#
# Im Browser läuft WKeePass ohne Rust: demo.js beantwortet alle Anfragen aus
# config/demo.json, alles bleibt im Speicher des Tabs. Es gibt keine echte
# Datenbank und nichts, was irgendwohin gespeichert würde — nach dem Neuladen
# ist alles wie vorher.
#
# Kopiert wird src-ui mit den Bibliotheken als echte Dateien (lokal ist
# libs/ ein Symlink), dazu ein Hinweis oben auf der Seite.

set -euo pipefail

ZIEL=${1:?Zielordner angeben, etwa ../../wuefl/wkeepass/demo}
QUELLE="$(cd "$(dirname "$0")/.." && pwd)/src-ui"

mkdir -p "$ZIEL"
rsync -aL --delete \
  --exclude build-single.mjs \
  --exclude request.html \
  --exclude '*.md' \
  --exclude 'libs/*/appdata' \
  "$QUELLE/" "$ZIEL/"

python3 - "$ZIEL/index.html" <<'PY'
import sys
pfad = sys.argv[1]
html = open(pfad, encoding='utf-8').read()

kopf = '''<meta name="robots" content="noindex">
<style>
  .demo-hinweis {
    position: fixed; z-index: 1000; inset-block-start: 0.5rem; inset-inline: 0; margin-inline: auto;
    width: fit-content; max-width: calc(100% - 1rem);
    display: flex; align-items: center; gap: 0.5rem;
    padding: 0.35rem 0.5rem 0.35rem 0.85rem; border-radius: 999px;
    font: 0.8rem/1.3 system-ui, sans-serif; color: #fff;
    background: linear-gradient(90deg, #26A269, #0a6aae); box-shadow: 0 2px 10px rgb(0 0 0 / 0.25);
  }
  .demo-hinweis a { color: inherit; font-weight: 600; }
  .demo-hinweis button { border: none; background: rgb(255 255 255 / 0.2); color: inherit;
    border-radius: 999px; width: 1.5rem; height: 1.5rem; cursor: pointer; flex: none; }
</style>
'''
hinweis = '''<div class="demo-hinweis" role="note">
  <span><b>Demo</b> – Master-Passwort beliebig. Alles bleibt in diesem Tab und ist nach dem Neuladen weg.
  <a href="../">Zu WKeePass</a></span>
  <button type="button" aria-label="Hinweis schließen" onclick="this.parentElement.remove()">✕</button>
</div>
'''
assert '</head>' in html and '<body' in html
html = html.replace('</head>', kopf + '</head>', 1)
start = html.index('>', html.index('<body')) + 1
html = html[:start] + '\n' + hinweis + html[start:]
html = html.replace('<title>WKeePass</title>', '<title>WKeePass – Demo</title>', 1)
open(pfad, 'w', encoding='utf-8').write(html)
PY

echo "Demo liegt in $ZIEL"
