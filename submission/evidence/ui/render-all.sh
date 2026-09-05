#!/bin/bash
# Turn the recorded sessions into the images the deck uses. Line ranges crop long transcripts to the
# decisive part; every gap is marked with an ellipsis in the image and the full transcript sits in
# the matching .txt file.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
python3 render.py 01-ordinary-work.ansi           01-ordinary-work.png           2,4-5,7,9,15-16,19,21
python3 render.py 02-known-package.ansi           02-known-package.png           4-5,14
python3 render.py 03-unknown-package-stopped.ansi 03-unknown-package-stopped.png 4-5,9
python3 render.py 04-secret-upload-blocked.ansi   04-secret-upload-blocked.png   23-26,49
python3 render.py 05-secret-upload-baseline.ansi  05-secret-upload-baseline.png  23,29
python3 render.py 06-workspace-wipe-baseline.ansi 06-workspace-wipe-baseline.png 4-5,9
python3 render.py 07-workspace-wipe-stopped.ansi  07-workspace-wipe-stopped.png  4-5,9
python3 render.py 08-ancestor-wipe-denied.ansi    08-ancestor-wipe-denied.png    4-7,29
python3 render.py 09-private-key-denied.ansi      09-private-key-denied.png      4-7
# The AI pair: the same two actions, different words in the README.
python3 render.py 10-ai-injection-stopped.ansi    10-ai-injection-stopped.png    4,9,11-12,18
python3 render.py 11-ai-ordinary-work.ansi        11-ai-ordinary-work.png        4,7-8,10,13
