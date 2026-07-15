#!/usr/bin/env bash

set -euo pipefail


readonly COLOR_GREEN='\033[0;32m'
readonly COLOR_RED='\033[0;31m'
readonly COLOR_YELLOW='\033[1;33m'
readonly COLOR_BLUE='\033[0;34m'
readonly COLOR_RESET='\033[0m'


readonly JADX_INSTALL_DIR="/opt/jadx"
readonly JADX_BIN_LINK="/usr/local/bin/jadx"
readonly APKTOOL_WRAPPER="/usr/local/bin/apktool"
readonly APKTOOL_JAR="/usr/local/bin/apktool.jar"
readonly APKTOOL_WRAPPER_URL="https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool"

TMP_DIR="$(mktemp -d)"

log_ok()    { echo -e "${COLOR_GREEN}[✓]${COLOR_RESET} $1"; }
log_fail()  { echo -e "${COLOR_RED}[✗]${COLOR_RESET} $1"; }
log_info()  { echo -e "${COLOR_BLUE}[*]${COLOR_RESET} $1"; }
log_warn()  { echo -e "${COLOR_YELLOW}[!]${COLOR_RESET} $1"; }

die() {
    local code="$1"
    shift
    log_fail "$*"
    cleanup
    exit "$code"
}

cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

if [[ "$(id -u)" -eq 0 ]]; then
    SUDO=""
else
    if ! command -v sudo >/dev/null 2>&1; then
        die 3 "This script needs root privileges (sudo not found). Please run as root."
    fi
    SUDO="sudo"
fi


DOWNLOADER=""
if command -v curl >/dev/null 2>&1; then
    DOWNLOADER="curl"
elif command -v wget >/dev/null 2>&1; then
    DOWNLOADER="wget"
else
    die 3 "Neither curl nor wget is available. Please install one of them and re-run."
fi


download() {
    local url="$1"
    local output="$2"

    log_info "Downloading: $url"

    if [[ "$DOWNLOADER" == "curl" ]]; then
        if ! curl -fsSL --retry 3 -o "$output" "$url"; then
            die 1 "Download failed for $url"
        fi
    else
        if ! wget -q --tries=3 -O "$output" "$url"; then
            die 1 "Download failed for $url"
        fi
    fi

    if [[ ! -s "$output" ]]; then
        die 1 "Downloaded file is empty or missing: $output"
    fi
}


fetch_json() {
    local url="$1"
    if [[ "$DOWNLOADER" == "curl" ]]; then
        curl -fsSL "$url" || die 1 "Failed to query GitHub API: $url"
    else
        wget -q -O - "$url" || die 1 "Failed to query GitHub API: $url"
    fi
}


latest_asset_url() {
    local repo="$1"
    local pattern="$2"
    local api_url="https://api.github.com/repos/${repo}/releases/latest"
    local json
    json="$(fetch_json "$api_url")"

    local url
    url="$(echo "$json" \
        | grep -o '"browser_download_url": *"[^"]*"' \
        | sed -E 's/"browser_download_url": *"([^"]*)"/\1/' \
        | grep -E "$pattern" \
        | head -n 1)"

    if [[ -z "$url" ]]; then
        die 1 "Could not locate a matching release asset for $repo (pattern: $pattern)"
    fi
    echo "$url"
}

install_unzip() {
    log_info "Installing unzip via apt-get..."

    if ! $SUDO apt-get update -qq; then
        die 2 "apt-get update failed. Check your network/package sources."
    fi

    if ! $SUDO apt-get install -y -qq unzip; then
        die 2 "apt-get install unzip failed."
    fi

    if ! command -v unzip >/dev/null 2>&1; then
        die 2 "unzip installation could not be verified."
    fi

    log_ok "unzip installed successfully."
}

check_unzip() {
    if command -v unzip >/dev/null 2>&1; then
        log_ok "unzip found"
    else
        log_fail "unzip not found"
        install_unzip
    fi
}

install_jadx() {
    log_info "Fetching latest JADX release info..."
    local asset_url
    asset_url="$(latest_asset_url "skylot/jadx" '^https.*jadx-[0-9][^/]*\.zip$')"

    local zip_path="${TMP_DIR}/jadx.zip"
    download "$asset_url" "$zip_path"

    log_info "Installing JADX to ${JADX_INSTALL_DIR}..."
    $SUDO mkdir -p "$JADX_INSTALL_DIR"

    if ! $SUDO unzip -oq "$zip_path" -d "$JADX_INSTALL_DIR"; then
        die 2 "Failed to extract JADX archive."
    fi

    if [[ ! -f "${JADX_INSTALL_DIR}/bin/jadx" ]]; then
        die 2 "JADX archive did not contain expected bin/jadx executable."
    fi

    $SUDO chmod +x "${JADX_INSTALL_DIR}/bin/jadx" "${JADX_INSTALL_DIR}/bin/jadx-gui" 2>/dev/null || true
    $SUDO ln -sf "${JADX_INSTALL_DIR}/bin/jadx" "$JADX_BIN_LINK"

    if ! command -v jadx >/dev/null 2>&1; then
        die 2 "JADX installation could not be verified (command not found after install)."
    fi

    log_ok "JADX installed successfully."
}

check_jadx() {
    if command -v jadx >/dev/null 2>&1; then
        log_ok "JADX found"
    else
        log_fail "JADX not found"
        install_jadx
    fi
}


install_apktool() {
    log_info "Fetching latest APKTool release info..."
    local jar_url
    jar_url="$(latest_asset_url "iBotPeaches/Apktool" '^https.*apktool_[0-9][^/]*\.jar$')"

    local wrapper_path="${TMP_DIR}/apktool"
    local jar_path="${TMP_DIR}/apktool.jar"

    download "$APKTOOL_WRAPPER_URL" "$wrapper_path"
    download "$jar_url" "$jar_path"

    log_info "Installing APKTool to /usr/local/bin..."
    $SUDO install -m 755 "$wrapper_path" "$APKTOOL_WRAPPER"
    $SUDO install -m 644 "$jar_path" "$APKTOOL_JAR"

    if ! command -v apktool >/dev/null 2>&1; then
        die 2 "APKTool installation could not be verified (command not found after install)."
    fi

    log_ok "APKTool installed successfully."
}

check_apktool() {
    if command -v apktool >/dev/null 2>&1; then
        log_ok "APKTool found"
    else
        log_fail "APKTool not found"
        install_apktool
    fi
}

main() {
    echo -e "${COLOR_BLUE}=====================================${COLOR_RESET}"
    echo -e "${COLOR_BLUE}  APKX-Hunter Dependency Installer${COLOR_RESET}"
    echo -e "${COLOR_BLUE}=====================================${COLOR_RESET}"
    echo

    # unzip first, since JADX installation depends on it.
    check_unzip
    check_jadx
    check_apktool

    echo
    echo -e "${COLOR_GREEN}All dependencies are present. Done.${COLOR_RESET}"
}

main "$@"
