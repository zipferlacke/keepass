#!/usr/bin/env python3
"""Prüft die Sprachdateien in appdata/lang/.

  tools/sprachen.py           prüfen
  tools/sprachen.py --fehlt   nur auflisten, was in einer Sprache fehlt

Geprüft wird:
  - jeder Schlüssel aus t('…'), tListe('…') und data-i18n…="…" steht in de_DE.json
  - jede Sprache hat dieselben Schlüssel wie de_DE.json (keinen mehr, keinen weniger)
  - Platzhalter {name} stimmen zwischen den Sprachen überein
Schlüssel, die im Code zusammengesetzt werden (t(`a.${b}`)), prüft das
Skript nicht; sie stehen mit einem Kommentar `// i18n: a.x a.y` daneben.
"""
import json, pathlib, re, sys

wurzel = pathlib.Path(__file__).resolve().parent.parent / 'src-ui'
lang = wurzel.parent / 'appdata' / 'lang'


def flach(baum, weg=''):
    out = {}
    for k, v in baum.items():
        p = f'{weg}.{k}' if weg else k
        # Einzahl/Mehrzahl gilt als ein Text.
        if isinstance(v, dict) and not (set(v) <= {'zero', 'one', 'two', 'few', 'many', 'other'} and 'other' in v):
            out.update(flach(v, p))
        else:
            out[p] = v
    return out


def platzhalter(wert):
    text = json.dumps(wert, ensure_ascii=False)
    return set(re.findall(r'\{(\w+)\}', text))


grund = flach(json.loads((lang / 'de_DE.json').read_text()))
fehler = []

genutzt = set()
muster = [
    re.compile(r"""\b(?:t|tListe|tSicher)\(\s*['"]([\w.\-äöüß]+)['"]"""),
    re.compile(r"""data-i18n(?:-[a-z\-]+)?="([\w.\-äöüß]+)\""""),
    re.compile(r"""//\s*i18n:\s*([\w.\-äöüß ]+)"""),
]
for datei in list(wurzel.glob('js/**/*.js')) + list(wurzel.glob('*.html')):
    if datei.name == 'i18n.js':
        continue
    text = datei.read_text()
    for m in muster:
        for treffer in m.findall(text):
            for k in treffer.split():
                genutzt.add(k)
                if k not in grund:
                    fehler.append(f'{datei.relative_to(wurzel)}: „{k}“ fehlt in de_DE.json')

for datei in sorted(lang.glob('*_*.json')):
    if datei.name == 'de_DE.json':
        continue
    andere = flach(json.loads(datei.read_text()))
    for k in grund.keys() - andere.keys():
        fehler.append(f'{datei.name}: „{k}“ fehlt')
    for k in andere.keys() - grund.keys():
        fehler.append(f'{datei.name}: „{k}“ gibt es in de_DE.json nicht')
    for k in grund.keys() & andere.keys():
        if platzhalter(grund[k]) != platzhalter(andere[k]):
            fehler.append(f'{datei.name}: „{k}“ hat andere Platzhalter')

# Ein Schlüssel zählt auch als bloße Zeichenkette als benutzt (Tabellen,
# Bedingungen wie t(x ? 'a.b' : 'a.c')).
alles = '\n'.join(d.read_text() for d in wurzel.glob('js/**/*.js'))
for k in grund:
    if f"'{k}'" in alles or f'"{k}"' in alles:
        genutzt.add(k)
unbenutzt = sorted(grund.keys() - genutzt)
for f in fehler:
    print(f)
if unbenutzt and '--fehlt' not in sys.argv:
    print(f'(unbenutzt in de_DE.json: {len(unbenutzt)}' + (': ' + ', '.join(unbenutzt[:15]) if unbenutzt else '') + ')')
print(f'{len(grund)} Texte, {len(fehler)} Fehler')
sys.exit(1 if fehler else 0)
