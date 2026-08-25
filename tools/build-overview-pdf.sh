#!/usr/bin/env bash
#
# Build OVERVIEW.pdf from OVERVIEW.md, with the mermaid diagrams rendered.
#
# Everything runs in containers, so this needs Docker and nothing else -- no
# local pandoc, LaTeX, Chrome or node. Mermaid needs a real browser to lay a
# diagram out, which is why this cannot be done with a markdown converter alone.
#
#   1. mermaid-cli  renders each ```mermaid block to a PNG and rewrites the
#                   markdown to point at it (it bundles Chromium for this)
#   2. pandoc       markdown -> one self-contained HTML, images inlined as
#                   data URIs so step 3 has no files to resolve
#   3. chromium     prints that HTML to PDF, honouring print.css
#
# pandoc/latex has no arm64 image, which is why this prints through a browser
# rather than going through LaTeX.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$root/build/pdf"
title="Intelligent API Security Gateway"

mkdir -p "$work"
cp "$root/OVERVIEW.md" "$work/"
cp "$root/tools/overview-print.css" "$work/print.css"
rm -f "$work"/rendered-*.png "$work"/rendered.md

# -s 3 renders at 3x so the diagrams stay sharp when the PDF is zoomed or
# printed; -b white stops them inheriting a transparent background that some
# readers show as black.
docker run --rm -u "$(id -u):$(id -g)" -v "$work:/data" minlag/mermaid-cli \
  -i /data/OVERVIEW.md -o /data/rendered.md -e png -b white -s 3

docker run --rm -u "$(id -u):$(id -g)" -v "$work:/data" pandoc/core:latest \
  /data/rendered.md -o /data/overview.html \
  --standalone --embed-resources --css=/data/print.css \
  --metadata title="$title"

docker run --rm -u "$(id -u):$(id -g)" -v "$work:/data" \
  --entrypoint chromium minlag/mermaid-cli \
  --headless --no-sandbox --disable-gpu --disable-dev-shm-usage \
  --virtual-time-budget=10000 --no-pdf-header-footer \
  --print-to-pdf=/data/OVERVIEW.pdf /data/overview.html

cp "$work/OVERVIEW.pdf" "$root/OVERVIEW.pdf"
echo "wrote $root/OVERVIEW.pdf"
