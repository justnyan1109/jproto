#!/usr/bin/env bash
# jchat.sh NAME [NODE] — клиент jchat с постоянной идентичностью (dev).
#
#   scripts/jchat.sh alice                # нода по умолчанию (fedA, 127.0.0.1:9101)
#   scripts/jchat.sh bob 127.0.0.1:9102   # другая нода федерации
#
# Идентичность/пины живут в dev/ (gitignored) — переживают перезапуски.
# Терминатор чата интерактивный: /to, /msg, /post, /fetch … (/help).
set -euo pipefail
cd "$(dirname "$0")/.."

NAME=${1:?usage: scripts/jchat.sh NAME [node HOST:PORT]}
NODE=${2:-127.0.0.1:9101}
PY=python/.venv/bin/python

if [ ! -x "$PY" ]; then
    echo "нет python/.venv — создай: python3 -m venv python/.venv && python/.venv/bin/pip install -r python/requirements.txt" >&2
    exit 1
fi

mkdir -p dev/pins
ID="dev/$NAME.json"
if [ ! -f "$ID" ]; then
    echo "— новая идентичность $NAME" >&2
    PYTHONPATH=python "$PY" -m jproto_ref.chat keygen "$ID"
fi

echo "— $NAME → $NODE (ident: dev/$NAME.json, pins: dev/pins)" >&2
PYTHONPATH=python exec "$PY" -m jproto_ref.chat run --node "$NODE" --me "$ID" --pin-dir dev/pins
