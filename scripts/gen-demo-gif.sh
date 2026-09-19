#!/usr/bin/env bash
# Regenerate docs/assets/demo.gif — the animated terminal demo.
#
# Pipeline:  script(1) in a real PTY  ->  asciicast v2  ->  agg  ->  GIF
#   (VHS was the previous route; its bundled headless Chrome captures zero frames
#    under WSL, exiting 0 with an empty temp dir. This path has no browser.)
#
# Requires: util-linux `script`, `agg` (https://github.com/asciinema/agg),
#           JetBrains Mono installed, and a warm ~/.fad-checker cache.
#
# The run is --offline on purpose: deterministic (no network timing in the
# recording) and it is the headline capability — a full audit, zero packets.
# The fixture is the one carrying unresolvable/private coordinates, so the
# "Maven POM analysis" block shows the dependencies fad could NOT reach — the
# failure mode that otherwise reads as a clean scan.
#
# Geometry: 120x60 at font 13 / line-height 1.185 gives 952x940. The height is
# pinned to 940 to match the previous asset so the README layout is unchanged;
# 60 rows means the run scrolls ~11 lines, and the held final frame still carries
# the private-dependency block, the full database checklist and every finding.
set -euo pipefail
cd "$(dirname "$0")/.."

FIXTURE=test/fixtures/private-lib-detection
OUT=docs/assets/demo.gif
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

# 0. warm the cache once, online, so the recorded --offline run is instant + stable
node fad-checker.js -s "$FIXTURE" --no-report >/dev/null 2>&1 || true

# 1. capture in a PTY, keeping real inter-chunk timings and ANSI colour
TERM=xterm-256color script -q --logging-format classic \
  --log-out "$TMP/raw" --log-timing "$TMP/tim" \
  -c "stty cols 120 rows 60; node fad-checker.js -s $FIXTURE --offline --no-report" >/dev/null

# 2. -> asciicast v2 (adds the typed prompt line and the Tokyo Night palette)
node scripts/asciicast-from-script.js "$TMP/raw" "$TMP/tim" "$TMP/demo.cast" 120 60

# 3. -> GIF
agg --font-size 13 --line-height 1.185 --fps-cap 8 \
    --last-frame-duration 5 --idle-time-limit 1 "$TMP/demo.cast" "$OUT"

echo "wrote $OUT ($(identify -format '%wx%h' "$OUT[0]" 2>/dev/null || echo '?'), $(( $(stat -c%s "$OUT") / 1024 )) KB)"
