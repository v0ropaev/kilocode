#!/bin/bash
# Turn the recorded sessions into the images the deck uses. Line ranges crop long transcripts to the
# decisive part; every gap is marked with an ellipsis in the image and the full transcript sits in
# the matching .txt file.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
python3 render.py 01-ordinary-work.ansi           01-ordinary-work.png           3,5-6,8,10,16-17,20,22
python3 render.py 02-known-package.ansi           02-known-package.png           1,5-6,15
python3 render.py 03-unknown-package-stopped.ansi 03-unknown-package-stopped.png 1,5-6,10
python3 render.py 04-secret-upload-blocked.ansi   04-secret-upload-blocked.png   1,24-27,50
python3 render.py 05-secret-upload-baseline.ansi  05-secret-upload-baseline.png  1,24,30
python3 render.py 06-workspace-wipe-baseline.ansi 06-workspace-wipe-baseline.png 1,5-6,10
python3 render.py 07-workspace-wipe-stopped.ansi  07-workspace-wipe-stopped.png  1,5-6,10
python3 render.py 08-ancestor-wipe-denied.ansi    08-ancestor-wipe-denied.png    1,5-8,30
python3 render.py 09-private-key-denied.ansi      09-private-key-denied.png      1,5-8
# The AI pair: the same two actions, different words in the README.
python3 render.py 10-ai-injection-stopped.ansi    10-ai-injection-stopped.png    1,10,13
python3 render.py 11-ai-ordinary-work.ansi        11-ai-ordinary-work.png        1,9,17

# The same two captures again, for the pitch deck, in type a room can read.
#
# Type on a slide scales as font/width, not with the crop: the 14 px default in a 1180 px window
# lands near 7 pt across a 10-inch slide, and no amount of cropping changes that. 30 px in an 890 px
# window reaches ~22 pt, which is the organiser's floor. It costs columns — 46 instead of 118 — so
# these renders carry the two lines that decide the story: what the README said, and what the
# external service received. The sentence the person was shown is quoted on the slide beside them.
python3 render.py 10-ai-injection-stopped.ansi    pitch-injection.png            10,19 --width 890 --font 30
python3 render.py 11-ai-ordinary-work.ansi        pitch-benign.png               14,17 --width 890 --font 30
