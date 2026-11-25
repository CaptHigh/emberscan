#!/usr/bin/env bash
# EmberScan installer for Linux (Debian / Ubuntu / Kali).
#
#   ./scripts/install_linux.sh            # full install: OS tools + EmberScan
#   ./scripts/install_linux.sh --check    # verify an existing install, change nothing
#
# Run it as your normal user (it asks for sudo only for apt). Safe to re-run:
# it also repairs an install broken by a system Python upgrade.
#
# All real work is done by scripts/install.py; this wrapper only makes sure a
# usable python3 exists first. It exits non-zero and prints a red FAILED banner
# if EmberScan does not actually work at the end.

set -euo pipefail

RED=$'\033[0;31m'; YELLOW=$'\033[1;33m'; CYAN=$'\033[0;36m'; NC=$'\033[0m'
die() { printf '%s\n' "${RED}✗ $*${NC}" "${RED}INSTALLATION FAILED -- EmberScan is NOT installed.${NC}" >&2; exit 1; }
trap 'die "unexpected error on line $LINENO (command: $BASH_COMMAND)"' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"

# Running under sudo would create a root-owned venv in the user's checkout that the
# user then can't update. Drop back to the invoking user; apt steps use sudo themselves.
if [[ $EUID -eq 0 && -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    echo "${YELLOW}! Don't run this with sudo -- continuing as '${SUDO_USER}' (sudo is used only for apt).${NC}"
    trap - ERR
    exec sudo -u "$SUDO_USER" -H -- bash "$0" "$@"
fi

if [[ $EUID -eq 0 ]]; then SUDO=(); else SUDO=(sudo); fi

# Python >= 3.9 with venv support is the only thing install.py can't bootstrap itself.
py_ok() {
    command -v python3 >/dev/null 2>&1 &&
        python3 -c 'import sys, venv, ensurepip; sys.exit(sys.version_info < (3, 9))' >/dev/null 2>&1
}

if [[ " $* " != *" --check "* ]] && ! py_ok; then
    echo "${CYAN}==> Installing Python 3 + venv support (needs sudo)${NC}"
    command -v apt-get >/dev/null 2>&1 ||
        die "python3 (>= 3.9) with the venv module is required and apt-get is not available. Install them with your package manager, then re-run."
    if [[ $EUID -ne 0 ]] && ! command -v sudo >/dev/null 2>&1; then
        die "sudo is not installed. Re-run as root, or install python3 python3-venv python3-pip first."
    fi
    "${SUDO[@]}" apt-get update || die "'apt-get update' failed -- check your network connection / apt sources."
    PYVER="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || true)"
    "${SUDO[@]}" apt-get install -y python3 python3-venv python3-pip python3-dev ||
        die "could not install python3 / python3-venv via apt."
    # Debian ships ensurepip per minor version (python3.X-venv); best effort.
    [[ -n "$PYVER" ]] && "${SUDO[@]}" apt-get install -y "python${PYVER}-venv" >/dev/null 2>&1 || true
    py_ok || die "python3 still cannot create virtualenvs after installing python3-venv."
fi

trap - ERR
set +e
if [[ " $* " == *" --check "* ]]; then
    python3 "$REPO/scripts/install.py" "$@"
else
    python3 "$REPO/scripts/install.py" --with-external "$@"
fi
rc=$?
exit $rc
