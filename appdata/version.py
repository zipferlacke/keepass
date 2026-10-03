#!/usr/bin/env python3
"""
Versionsnummer überall eintragen – aus dem obersten Eintrag im Changelog
von appdata/messages.json:

    python3 appdata/version.py           eintragen, zeigt was sich ändert
    python3 appdata/version.py --pruefen nur prüfen (Rückgabe 1, wenn etwas abweicht)

Ziele:
    src-tauri/tauri.conf.json                 Version der App (Android: versionCode daraus)
    src-tauri/Cargo.toml                      Version des Rust-Pakets
    src-tauri/Cargo.lock                      dieselbe, damit Cargo nichts nachträgt
    flatpak/de.wuefl.wkeepass.metainfo.xml    oberste <release> mit Datum aus dem Changelog

git-release ruft das Skript mit --pruefen vor dem Tag auf, wenn es da ist.
Vorbild ist appdata/version.py in WMap; ohne Service Worker entfällt dort
die Dateiliste.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def target():
    log = json.loads((ROOT / 'appdata/messages.json').read_text(encoding='utf-8')).get('changelog') or []
    if not log or not re.fullmatch(r'\d+\.\d+\.\d+', str(log[0].get('version', ''))):
        sys.exit('messages.json: oberster Changelog-Eintrag ohne gültige Version (x.y.z)')
    return log[0]['version'], str(log[0].get('date', ''))


# Datei, Muster (Gruppe 1 = davor, Gruppe 2 = Version, Gruppe 3 = danach)
TARGETS = [
    ('src-tauri/tauri.conf.json', r'(\n  "version": ")([^"]+)(")'),
    ('src-tauri/Cargo.toml', r'(\[package\][^\[]*?\nversion = ")([^"]+)(")'),
    ('src-tauri/Cargo.lock', r'(\nname = "wkeepass"\nversion = ")([^"]+)(")'),
]

METAINFO = 'flatpak/de.wuefl.wkeepass.metainfo.xml'


def metainfo(version, date, check):
    """Die oberste <release> nennt Version und Datum; eine neue Version kommt oben dazu."""
    path = ROOT / METAINFO
    if not path.exists():
        return None
    text = path.read_text(encoding='utf-8')
    m = re.search(r'(<releases>\s*\n(\s*))<release version="([^"]+)" date="([^"]*)"/>', text)
    if not m:
        sys.exit(f'{METAINFO}: <releases> nicht gefunden')
    if m.group(3) == version and m.group(4) == date:
        return None
    zeile = f'<release version="{version}" date="{date}"/>'
    if m.group(3) == version:
        # Gleiche Version, anderes Datum: die Zeile ersetzen.
        neu = text[:m.end(1)] + zeile + text[m.end():]
        meldung = f'{METAINFO}: Datum {m.group(4)} → {date}'
    else:
        neu = text[:m.end(1)] + zeile + '\n' + m.group(2) + text[m.end(1):]
        meldung = f'{METAINFO}: <release> {version} vom {date} dazu'
    if not check:
        path.write_text(neu, encoding='utf-8')
    return meldung


def main():
    check = '--pruefen' in sys.argv[1:]
    version, date = target()
    off = []
    for rel, pattern in TARGETS:
        path = ROOT / rel
        if not path.exists():
            continue
        text = path.read_text(encoding='utf-8')
        m = re.search(pattern, text)
        if not m:
            sys.exit(f'{rel}: Versionsstelle nicht gefunden')
        if m.group(2) == version:
            continue
        off.append(f'{rel}: {m.group(2)} → {version}')
        if not check:
            path.write_text(text[:m.start(2)] + version + text[m.end(2):], encoding='utf-8')
    meta = metainfo(version, date, check)
    if meta:
        off.append(meta)
    if not off:
        print(f'Version {version} steht überall.')
        return 0
    print(('Weicht ab:' if check else f'Version {version} eingetragen:') + '\n  ' + '\n  '.join(off))
    return 1 if check else 0


if __name__ == '__main__':
    sys.exit(main())
