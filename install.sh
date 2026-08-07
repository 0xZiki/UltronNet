#!/bin/bash

GREEN="\e[32m"
BLUE="\e[34m"
RED="\e[31m"
RESET="\e[0m"

echo -e "${BLUE}[*] Starting UltronNet Installation...${RESET}"

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[!] Please run this script as root (sudo ./install.sh)${RESET}"
  exit 1
fi

INSTALL_DIR="/opt/UltronNet"
echo -e "${BLUE}[*] Copying files to ${INSTALL_DIR}...${RESET}"
mkdir -p "$INSTALL_DIR"
cp UltronNet.py "$INSTALL_DIR/"
cp requirements.txt "$INSTALL_DIR/"

echo -e "${BLUE}[*] Setting up Virtual Environment and installing requirements...${RESET}"
apt-get update -qq && apt-get install -y python3-venv -qq
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt" --quiet

BIN_PATH="/usr/local/bin/ultronNet"
echo -e "${BLUE}[*] Creating global command '${GREEN}ultronNet${BLUE}'...${RESET}"

cat << 'EOF' > "$BIN_PATH"
#!/bin/bash
# This is the wrapper script that will be executed when the user types ultronNet
# It runs Python from the venv and passes all arguments "$@"
# without changing the current working directory (CWD)
/opt/UltronNet/venv/bin/python3 /opt/UltronNet/UltronNet.py "$@"
EOF

chmod +x "$BIN_PATH"

echo -e "${GREEN}[✔] Installation Complete!${RESET}"
echo -e "You can now run the tool from anywhere by simply typing: ${GREEN}ultronNet${RESET}"