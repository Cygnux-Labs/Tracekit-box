#!/bin/sh
# Renders docs/readme/banner.png from banner.html at 2x with headless Chrome (fonts load from Google Fonts).
# usage: docs/readme/src/render.sh   (from the repository root)
set -e
cd "$(dirname "$0")"
CHROME=${CHROME:-"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}
"$CHROME" --headless=new --disable-gpu --hide-scrollbars --allow-file-access-from-files --force-device-scale-factor=2 \
  --window-size=1280,420 --virtual-time-budget=6000 --default-background-color=00000000 \
  --screenshot="../banner.png" "file://$PWD/banner.html" 2>/dev/null
