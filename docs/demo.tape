# VHS tape — generate an animated GIF of a fad-checker run.
#   1. install VHS:  https://github.com/charmbracelet/vhs   (brew install vhs)
#   2. point PROJECT below at a real checkout, or use a bundled test fixture
#      (a warm ~/.fad-checker cache makes the --offline run instant and
#      deterministic — ideal for recording)
#   3. render:        vhs docs/demo.tape   ->   docs/assets/demo.gif
#
# The static cli.png / report.png in this folder are regenerated from
# test/fixtures/polyglot via a headless-Chromium screenshot of the colored
# terminal output and of the generated HTML report — see the project README.
#
# Tip: do one online run first so the caches are warm, then record --offline.

Output docs/assets/demo.gif

Set Theme "Tokyo Night"
Set FontFamily "JetBrains Mono"
Set FontSize 18
Set Width 1200
Set Height 760
Set Padding 24
Set PlaybackSpeed 1.0

Hide
Type "PROJECT=./test/fixtures/polyglot" Enter
Show

Type "fad -s $PROJECT --offline --no-transitive" Sleep 600ms Enter
Sleep 9s
