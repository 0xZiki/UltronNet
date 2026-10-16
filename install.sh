#!/usr/bin/env bash
set -e
echo "[*] Installing UltronNet v2.1 system-wide..."
pip install -e . --break-system-packages
echo "[+] Successfully installed! You can now run 'ultronnet' from anywhere."
