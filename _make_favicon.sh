#!/bin/bash
set -e
cd "$(dirname "$0")"

CMD=$(command -v magick || command -v convert)
if [ -z "$CMD" ]; then
  echo "Error: ImageMagick not found. Please install it first."
  exit 1
fi

$CMD convert -background transparent "images/icon.png" \
  -define icon:auto-resize=16,24,32,48,64,72,96,128,256 "favicon.ico"