#!/usr/bin/env bash
# Nach der Begrüßung fragt die App einmal, was ins Netz darf: fünf Schalter,
# E-Mail-Prüfung und Löschanleitungen ab Werk aus. Prüft pages/lock.js
# (showOnlineQuestion) und config/settings.default.json.
set -euo pipefail
cd "$(dirname "$0")/../.."
tests/oberflaeche/lauf.sh "#wc-skip,?#online-ok,?[data-online='icons.download']:checked,?[data-online='checks.passwordBreach']:checked,?[data-online='checks.emailBreach']:not(:checked),?[data-online='checks.deletionLinks']:not(:checked),#online-ok,!#online-ok,?#lock-pick" "${1:-}"
