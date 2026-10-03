#!/usr/bin/env bash
#
# Oberflächentest: die App als Demo im Browser, eine Folge von Schritten,
# und die Konsole als Text.
#
#   tests/oberflaeche/lauf.sh "#wc-skip,#lock-pick" [bild.png] [breite] [hoehe]
#
# Ein Schritt mit „:::" schreibt in ein Feld, alles andere wird geklickt.
# Ohne Tauri antwortet js/data/demo.js aus config/demo.json — es gibt
# keine echte Datei und nichts, was gespeichert würde.
set -euo pipefail
wurzel="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$wurzel"

klicks="${1:-}"
bild="${2:-}"
breite="${3:-1200}"
hoehe="${4:-900}"

python3 - "$klicks" <<'PY'
import json, pathlib, sys
schritte = json.dumps([s for s in sys.argv[1].split(',') if s.strip()])

# Der Fänger muss als Erstes laufen: Scheitert schon ein Modul beim Laden,
# ist ein später eingebundenes Modul noch nicht da, um das zu melden.
# Deshalb steht er als gewöhnliches Skript ganz oben im Kopf.
faenger = """<script>
(() => {
  const melde = (art, text) => {
    try { navigator.sendBeacon('/__log', art + '\\t' + text); } catch (e) { /* egal */ }
  };
  window.__melde = melde;
  for (const art of ['log', 'info', 'warn', 'error']) {
    const alt = console[art].bind(console);
    console[art] = (...a) => { melde(art.toUpperCase(), a.map(x => x && x.stack ? x + ' | ' + x.stack : String(x)).join(' ')); alt(...a); };
  }
  addEventListener('error', e => melde('ERROR', e.error
    ? e.error + ' | ' + e.error.stack
    : (e.message + ' @ ' + (e.filename || '') + ':' + (e.lineno || ''))), true);
  addEventListener('unhandledrejection', e => melde('ERROR',
    'unbehandelt: ' + ((e.reason && e.reason.stack) || e.reason)));
})();
</script>
"""

anhang = f"""
<img src="/__sleep" alt="" width="1" height="1" style="position:fixed;opacity:0">
<script type="module">
import {{ schritte }} from '/tests/lib/melden.js';
schritte({schritte});
</script>
"""
seite = pathlib.Path('src-ui/index.html').read_text()
seite = seite.replace('<head>', '<head>\n' + faenger, 1).replace('</body>', anhang + '</body>')
pathlib.Path('src-ui/_test.html').write_text(seite)
PY
trap 'rm -f src-ui/_test.html' EXIT

schritte=$(awk -F, '{print NF}' <<<"$klicks")
tests/lib/lauf.sh src-ui/_test.html "$(( 3 + schritte ))" "$bild" "$breite" "$hoehe"
