#!/usr/bin/env bash
#
# Rauchprobe der Oberfläche
# ------------------------------------------------------------------
# Startet die App als Demo im Browser (ohne Tauri; die Antworten kommen
# aus js/demo.js und config/demo.json), fängt jeden Fehler ab und schreibt
# ihn sichtbar auf die Seite. Danach ein Bild davon.
#
#   tools/smoke.sh [bild.png] [breite] [hoehe] ["#klick1,#klick2"]
#
# Die Knöpfe werden der Reihe nach gedrückt, bevor das Bild entsteht —
# so kommt man über die Willkommensseite hinaus:
#
#   tools/smoke.sh /tmp/liste.png 1200 900 "#wc-skip,#lock-pick,#fld-pw=egal,.dialog_submit"
#
# Ein Schritt mit „=" schreibt in ein Feld statt zu klicken.
#
# Grün unten: keine Fehler. Rot: die Fehler stehen da.
#
# Firefox macht das Bild beim load-Ereignis. Damit vorher noch geklickt
# werden kann, hält ein absichtlich langsames Bild (/__sleep) das Laden
# auf — der kleine Server unten liefert es.
set -euo pipefail
cd "$(dirname "$0")/.."

ziel="${1:-/tmp/wkeepass-smoke.png}"
breite="${2:-1200}"
hoehe="${3:-900}"
klicks="${4:-}"
port="${PORT:-8749}"
profil="$(mktemp -d)"

python3 - "$klicks" <<'PY'
import pathlib, sys, json
klicks = json.dumps([s for s in sys.argv[1].split(',') if s.strip()])
faenger = '''
<img src="/__sleep" alt="" width="1" height="1" style="position:fixed;opacity:0">
<div id="smoke" style="position:fixed;inset:auto 0 0 0;z-index:99999;background:#0a0;color:#fff;font:14px monospace;padding:.5rem;white-space:pre-wrap;max-height:40vh;overflow:auto">Rauchprobe: keine Fehler</div>
<script>
(() => {
  const box = () => document.getElementById('smoke');
  const fehler = [];
  const zeige = t => {
    fehler.push(t);
    const b = box();
    if (b) { b.style.background = '#a00'; b.textContent = fehler.join('\\n'); }
  };
  addEventListener('error', e => zeige(`${e.message ?? e.error} @ ${e.filename ?? ''}:${e.lineno ?? ''}`), true);
  addEventListener('unhandledrejection', e => zeige(`unhandled: ${e.reason?.message ?? e.reason}`));
  const alt = console.error;
  console.error = (...a) => { zeige('console.error: ' + a.map(String).join(' ')); alt(...a); };

  const warte = ms => new Promise(r => setTimeout(r, ms));
  (async () => {
    await warte(900);
    for (const schritt of KLICKS) {
      // "#feld=wert" schreibt in ein Eingabefeld, alles andere wird geklickt.
      const teil = schritt.indexOf('=');
      const sel = teil > 0 ? schritt.slice(0, teil) : schritt;
      const el = document.querySelector(sel);
      if (!el) { zeige(`Nicht da: ${sel}`); continue; }
      if (teil > 0) {
        el.value = schritt.slice(teil + 1);
        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
      } else {
        el.click();
      }
      await warte(700);
    }
  })();
})();
</script>
'''.replace('KLICKS', klicks)
quelle = pathlib.Path('src-ui/index.html').read_text()
pathlib.Path('src-ui/_smoke.html').write_text(quelle.replace('</body>', faenger + '</body>'))
PY

# Wie lange das Laden aufgehalten wird: genug für alle Schritte.
schritte=$(awk -F, '{print NF}' <<<"$klicks")
wartezeit=$(( 3 + schritte ))

python3 - "$port" "$wartezeit" <<'PY' &
import http.server, functools, sys, time, socketserver

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Hält das load-Ereignis auf, damit vorher geklickt werden kann.
        if self.path.startswith('/__sleep'):
            time.sleep(float(sys.argv[2]))
            bild = bytes.fromhex('89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000a49444154789c6360000002000100ffff03000006000557bfabd40000000049454e44ae426082')
            self.send_response(200)
            self.send_header('Content-Type', 'image/png')
            self.send_header('Content-Length', str(len(bild)))
            self.end_headers()
            self.wfile.write(bild)
            return
        super().do_GET()

    def log_message(self, *a):
        pass

socketserver.ThreadingTCPServer.allow_reuse_address = True
with socketserver.ThreadingTCPServer(('', int(sys.argv[1])),
        functools.partial(Handler, directory='src-ui')) as srv:
    srv.serve_forever()
PY
server=$!
trap 'kill $server 2>/dev/null || true; rm -f src-ui/_smoke.html; rm -rf "$profil"' EXIT
sleep 1

firefox --headless --profile "$profil" --screenshot "$ziel" \
        --window-size="$breite,$hoehe" "http://localhost:$port/_smoke.html" >/dev/null 2>&1

echo "Bild: $ziel"
