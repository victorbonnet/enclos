#!/bin/sh
set -eu
python3 - "$1" <<'PY'
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
text = path.read_text().removesuffix('\n[network]\nlisten = true\n')
if 'listen = true' not in text:
    text = text.replace('[network]\n', '[network]\nlisten = true\n', 1)
path.write_text(text)
PY
