#!/bin/bash
# Fortrix macOS Agent — Install Script
# Usage: sudo bash install.sh

set -euo pipefail

BIN_NAME="fortrix-agent"
INSTALL_DIR="/usr/local/fortrix"
BIN_PATH="${INSTALL_DIR}/${BIN_NAME}"
PLIST_PATH="/Library/LaunchDaemons/com.fortrix.agent.plist"
CONFIG_PATH="${INSTALL_DIR}/fortrix-agent.json"

echo "=== Fortrix macOS Agent Installer ==="

# Check root
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: must run as root (sudo bash install.sh)"
    exit 1
fi

# Ensure install directory
mkdir -p "${INSTALL_DIR}"

# Copy binary
if [[ -f "./${BIN_NAME}" ]]; then
    cp "./${BIN_NAME}" "${BIN_PATH}"
elif [[ -f "./${BIN_NAME}-darwin-amd64" ]]; then
    cp "./${BIN_NAME}-darwin-amd64" "${BIN_PATH}"
elif [[ -f "./${BIN_NAME}-darwin-arm64" ]]; then
    cp "./${BIN_NAME}-darwin-arm64" "${BIN_PATH}"
else
    echo "ERROR: ${BIN_NAME} binary not found in current directory"
    echo "       Build it first: GOOS=darwin GOARCH=amd64 go build -o ${BIN_NAME}-darwin-amd64 ."
    echo "       Or: GOOS=darwin GOARCH=arm64 go build -o ${BIN_NAME}-darwin-arm64 ."
    exit 1
fi

chmod 755 "${BIN_PATH}"

# Install launchd plist
cp "./com.fortrix.agent.plist" "${PLIST_PATH}"

# Prompt for server + enroll key
read -rp "Server URL [https://fortrix.xyz]: " SERVER_URL
SERVER_URL="${SERVER_URL:-https://fortrix.xyz}"
read -rp "Enroll Key: " ENROLL_KEY

# Write initial program arguments to plist (launchd passes them as argv)
# We'll use a wrapper approach: set ProgramArguments in plist via sed
if [[ -n "${ENROLL_KEY}" ]]; then
    # First run: enroll mode
    /usr/libexec/PlistBuddy -c "Add :ProgramArguments array" "${PLIST_PATH}" 2>/dev/null || /usr/libexec/PlistBuddy -c "Delete :ProgramArguments" "${PLIST_PATH}"
    /usr/libexec/PlistBuddy -c "Add :ProgramArguments array" "${PLIST_PATH}"
    /usr/libexec/PlistBuddy -c "Add :ProgramArguments:0 string ${BIN_PATH}" "${PLIST_PATH}"
    /usr/libexec/PlistBuddy -c "Add :ProgramArguments:1 string -server" "${PLIST_PATH}"
    /usr/libexec/PlistBuddy -c "Add :ProgramArguments:2 string ${SERVER_URL}" "${PLIST_PATH}"
    /usr/libexec/PlistBuddy -c "Add :ProgramArguments:3 string -enroll" "${PLIST_PATH}"
    /usr/libexec/PlistBuddy -c "Add :ProgramArguments:4 string ${ENROLL_KEY}" "${PLIST_PATH}"
    /usr/libexec/PlistBuddy -c "Add :ProgramArguments:5 string -config" "${PLIST_PATH}"
    /usr/libexec/PlistBuddy -c "Add :ProgramArguments:6 string ${CONFIG_PATH}" "${PLIST_PATH}"

    # After first enrollment, we should switch to no-enroll mode.
    # launchd KeepAlive will restart; on second run device_token exists, -enroll ignored.
fi

# Load the daemon
launchctl bootstrap system "${PLIST_PATH}" 2>/dev/null || launchctl load "${PLIST_PATH}"

echo ""
echo "=== Installation Complete ==="
echo "Binary:   ${BIN_PATH}"
echo "Config:   ${CONFIG_PATH}"
echo "Service:  ${PLIST_PATH}"
echo ""
echo "Check status:  sudo launchctl list com.fortrix.agent"
echo "View logs:     tail -f /var/log/fortrix-agent.log"
echo "Uninstall:     sudo launchctl unload ${PLIST_PATH} && sudo rm -rf ${INSTALL_DIR} ${PLIST_PATH}"
