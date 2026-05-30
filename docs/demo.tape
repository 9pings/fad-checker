# VHS tape — generate an animated GIF of a fad-checker run.
#   1. install VHS:  https://github.com/charmbracelet/vhs   (brew install vhs)
#   2. point PROJECT below at a real checkout (a warm ~/.fad-checker cache makes
#      the --offline run instant and deterministic — ideal for recording)
#   3. render:        vhs docs/demo.tape   ->   docs/assets/demo.gif
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
Type "PROJECT=./your-project" Enter
Show

Type "fad -s $PROJECT --offline" Sleep 600ms Enter
Sleep 9s
