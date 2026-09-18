#!/usr/bin/env python3
"""Der Server, der die Oberfläche beim Entwickeln ausliefert.

Er tut dasselbe wie ``python3 -m http.server`` und **eines** mehr: Er
verbietet dem Webview, irgendetwas zwischenzuspeichern.

Warum das nötig ist
-------------------

``http.server`` schickt zu jeder Datei ein ``Last-Modified`` und sonst
nichts. Fehlt ``Cache-Control``, darf ein Client nach RFC 9111 selbst
schätzen, wie lange die Antwort frisch bleibt; die übliche Faustregel ist
ein Zehntel der Zeit seit der letzten Änderung. Eine Datei, die vor zehn
Tagen zuletzt angefasst wurde, gilt damit einen Tag lang als frisch und
wird nicht einmal nachgefragt.

Beim Entwickeln ist das genau verkehrt herum: Ausgerechnet die Dateien, an
denen man länger nicht gearbeitet hat, hängen am hartnäckigsten fest. Man
ändert etwas, lädt neu, und sieht den alten Stand.

``no-store`` schneidet das ab — der Webview darf die Antwort gar nicht erst
ablegen. Das kostet beim Neuladen ein paar Millisekunden über den lokalen
Netzanschluss und ist damit bezahlt.

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

# Auf dem Handy läuft die Oberfläche nicht auf demselben Gerät: Beim Aufruf
# von `cargo tauri android dev --host` setzt Tauri `TAURI_DEV_HOST` auf die
# Adresse dieses Rechners im WLAN, und dann muss der Server auch dort
# lauschen — auf 127.0.0.1 käme das Handy nie an.
HOST = os.environ.get("TAURI_DEV_HOST", "127.0.0.1")
PORT = 1420
ROOT = "src-ui"

# Bilder liegen in appdata/ — ausgeliefert unter ihrem Namen in der Wurzel.
# Die gebaute Fassung bekommt sie über build.rs nach src-ui/ kopiert.
APPDATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "appdata")
BILDER = {"/logo.svg", "/logo.png"}


class NoCacheHandler(http.server.SimpleHTTPRequestHandler):
    """Wie der eingebaute Handler, nur ohne Zwischenspeicher."""

    def end_headers(self):
        # no-store ist der schärfste der drei: nicht ablegen, Punkt.
        # Die beiden anderen sind für alte Zwischenspeicher, die noch nach
        # HTTP/1.0 denken.
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
        # Jede einzelne Datei zu protokollieren macht die Ausgabe von
        # `cargo tauri dev` unlesbar. Fehler bleiben sichtbar.
        code = args[1] if len(args) > 1 else ""
        if str(code).startswith(("4", "5")):
            super().log_message(fmt, *args)


def already_serving(port):
    """Läuft auf dem Port schon *unsere* Oberfläche?

    Ein übriggebliebener Server aus einem früheren Lauf ist kein Grund, den
    ganzen Start abzubrechen — er tut ja genau das Richtige. Ein *fremder*
    Dienst dagegen schon: Der lieferte etwas anderes aus, und die App zeigte
    wortlos die falsche Seite. Deshalb wird nachgesehen, was dort antwortet.
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
