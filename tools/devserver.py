#!/usr/bin/env python3
"""Der Server, der die Oberfläche beim Entwickeln ausliefert.

Er verhält sich wie ``python3 -m http.server``, verbietet dem Webview aber
jedes Zwischenspeichern: Jede Antwort trägt ``Cache-Control: no-store``.

``http.server`` sendet nur ``Last-Modified``. Ohne ``Cache-Control`` darf ein
Client nach RFC 9111 die Frischedauer selbst schätzen, üblicherweise ein
Zehntel der Zeit seit der letzten Änderung. Selten geänderte Dateien gelten
dadurch lange als frisch und werden nicht neu angefragt; ``no-store`` verhindert
das.

Nur zum Entwickeln. In der gebauten Fassung steckt die Oberfläche über
``frontendDist`` im Programm selbst; dann läuft hier gar nichts.

Aufruf::

    python3 tools/devserver.py [verzeichnis] [port]
"""

import errno
import functools
import http.server
import os
import sys

# Bei `cargo tauri android dev --host` läuft die Oberfläche auf einem anderen
# Gerät. Tauri setzt dann `TAURI_DEV_HOST` auf die WLAN-Adresse dieses Rechners,
# auf der der Server lauschen muss.
HOST = os.environ.get("TAURI_DEV_HOST", "127.0.0.1")
PORT = 1420
ROOT = "src-ui"

# Bilder liegen in appdata/ und werden unter ihrem Namen in der Wurzel
# ausgeliefert. Die gebaute Fassung erhält sie über build.rs in src-ui/.
APPDATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "appdata")
BILDER = {"/logo.svg", "/logo.png"}


class NoCacheHandler(http.server.SimpleHTTPRequestHandler):
    """Wie der eingebaute Handler, nur ohne Zwischenspeicher."""

    def end_headers(self):
        # no-store verbietet das Ablegen; Pragma und Expires gelten für
        # Zwischenspeicher, die nur HTTP/1.0 kennen.
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()

    def translate_path(self, path):
        rein = path.split("?", 1)[0].split("#", 1)[0]
        if rein in BILDER:
            return os.path.join(APPDATA, rein.lstrip("/"))
        return super().translate_path(path)

    def log_message(self, fmt, *args):
        # Einzelne Dateizugriffe werden nicht protokolliert, Fehler schon.
        code = args[1] if len(args) > 1 else ""
        if str(code).startswith(("4", "5")):
            super().log_message(fmt, *args)


def already_serving(port):
    """Läuft auf dem Port schon *unsere* Oberfläche?

    Ein Server aus einem früheren Lauf wird weiterverwendet; ein fremder
    Dienst auf dem Port führt zum Abbruch. Geprüft wird die Antwort der
    Startseite.
    """
    import urllib.request

    try:
        with urllib.request.urlopen(f"http://{HOST}:{port}/", timeout=2) as response:
            return b"WKeePass" in response.read(4096)
    except Exception:
        return False


def main(argv):
    root = argv[1] if len(argv) > 1 else ROOT
    port = int(argv[2]) if len(argv) > 2 else PORT

    handler = functools.partial(NoCacheHandler, directory=root)

    # Threading, weil der Webview viele Dateien gleichzeitig anfordert.
    try:
        httpd = http.server.ThreadingHTTPServer((HOST, port), handler)
    except OSError as err:
        if err.errno != errno.EADDRINUSE:
            raise

        if already_serving(port):
            print(f"Auf {HOST}:{port} läuft die Oberfläche bereits — weiter.")
            return

        print(
            f"FEHLER: {HOST}:{port} ist belegt, und dort antwortet nicht WKeePass.\n"
            f"        Wer es ist, zeigt:  ss -ltnp | grep :{port}",
            file=sys.stderr,
        )
        sys.exit(1)

    with httpd:
        print(f"Oberfläche aus {root}/ auf http://{HOST}:{port} — ohne Zwischenspeicher")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main(sys.argv)
