"""Kleiner Testserver: liefert das Projekt aus und nimmt die Konsole entgegen.

  python3 tests/lib/server.py <port> <sekunden>

* `/__log`  nimmt per POST eine Zeile „ART<tab>Text" und schreibt sie auf
  die Standardausgabe. So kommen Fehler aus dem Browser als Text heraus
  und nicht als Bild.
* `/__sleep` antwortet erst nach <sekunden> mit einem Pixel. Damit wartet
  das load-Ereignis, bis die Testschritte durch sind — Firefox knipst
  sonst zu früh und beendet sich.
"""
import functools, http.server, socketserver, sys, time

PIXEL = bytes.fromhex(
    '89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489'
    '0000000a49444154789c6360000002000100ffff03000006000557bfabd4000000'
    '0049454e44ae426082')


class Handler(http.server.SimpleHTTPRequestHandler):
    schlaf = 5.0

    def do_GET(self):
        if self.path.startswith('/__sleep'):
            time.sleep(self.schlaf)
            self.send_response(200)
            self.send_header('Content-Type', 'image/png')
            self.send_header('Content-Length', str(len(PIXEL)))
            self.end_headers()
            self.wfile.write(PIXEL)
            return
        super().do_GET()

    def do_POST(self):
        laenge = int(self.headers.get('Content-Length') or 0)
        text = self.rfile.read(laenge).decode('utf-8', 'replace')
        art, _, rest = text.partition('\t')
        print(f'{art:8} {rest}', flush=True)
        self.send_response(204)
        self.end_headers()

    def log_message(self, *a):
        pass


def main():
    port, sekunden = int(sys.argv[1]), float(sys.argv[2])
    Handler.schlaf = sekunden
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(('', port), Handler) as srv:
        srv.serve_forever()


main()
