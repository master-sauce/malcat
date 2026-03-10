#!/usr/bin/env bash
set -e

REPO="master-sauce/malcat"
BINARY_NAME="malcat"
INSTALL_DIR="$HOME/.local/bin"
RAW_BASE="https://raw.githubusercontent.com/${REPO}/main/malcat"

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[malcat]${NC} $*"; }
success() { echo -e "${GREEN}[malcat]${NC} $*"; }
warn()    { echo -e "${YELLOW}[malcat]${NC} $*"; }
error()   { echo -e "${RED}[malcat] ERROR:${NC} $*" >&2; exit 1; }

# ── Detect OS ─────────────────────────────────────────────────────────────────
OS="$(uname -s)"
case "$OS" in
  Linux*)  PLATFORM="linux" ;;
  Darwin*) PLATFORM="macos" ;;
  *)       error "Unsupported OS: $OS" ;;
esac

# ── Resolve where the binary actually lives ───────────────────────────────────
BINARY_PATH="$INSTALL_DIR/$BINARY_NAME"
GO_BIN=""
if command -v go &>/dev/null; then
  GO_BIN="$(go env GOPATH)/bin/$BINARY_NAME"
fi

is_installed() {
  [ -f "$BINARY_PATH" ] || { [ -n "$GO_BIN" ] && [ -f "$GO_BIN" ]; }
}

# ── Uninstall ─────────────────────────────────────────────────────────────────
uninstall() {
  echo ""
  info "Uninstalling malcat..."
  local removed=0

  if [ -f "$BINARY_PATH" ]; then
    rm -f "$BINARY_PATH"
    success "Removed binary: $BINARY_PATH"
    removed=1
  fi

  if [ -n "$GO_BIN" ] && [ -f "$GO_BIN" ]; then
    rm -f "$GO_BIN"
    success "Removed binary: $GO_BIN"
    removed=1
  fi

  [ "$removed" -eq 0 ] && warn "No binary found to remove."

  remove_from_rc() {
    local rc="$1"
    if [ ! -f "$rc" ]; then return; fi
    if grep -qF "malcat installer" "$rc" || grep -qF "$INSTALL_DIR" "$rc"; then
      TMP_RC="$(mktemp)"
      grep -v "# Added by malcat installer" "$rc" \
        | grep -v "export PATH.*$INSTALL_DIR" \
        | grep -v "set -gx PATH.*$INSTALL_DIR" \
        > "$TMP_RC"
      mv "$TMP_RC" "$rc"
      success "Removed PATH entry from $rc"
    fi
  }

  remove_from_rc "$HOME/.bashrc"
  remove_from_rc "$HOME/.bash_profile"
  remove_from_rc "$HOME/.zshrc"
  remove_from_rc "$HOME/.profile"
  remove_from_rc "$HOME/.config/fish/config.fish"

  echo ""
  success "✓ malcat has been uninstalled. Open a new terminal to clear your PATH."
  echo ""
  exit 0
}

# ── Toggle: if already installed, prompt to uninstall ─────────────────────────
if is_installed; then
  FOUND_AT="$BINARY_PATH"
  [ ! -f "$BINARY_PATH" ] && FOUND_AT="$GO_BIN"
  echo ""
  warn "malcat is already installed at $FOUND_AT"
  # Read from /dev/tty so this works when piped through bash (curl | bash)
  printf "  ${YELLOW}Uninstall it? [y/N]:${NC} "
  read -r CONFIRM < /dev/tty
  if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
    uninstall
  else
    info "Cancelled. No changes made."
    exit 0
  fi
fi

# ── Install ───────────────────────────────────────────────────────────────────
echo ""
echo -e "  ${CYAN}malcat Installer${NC}"
echo -e "  ─────────────────────────────────────"
echo ""

install_via_download() {
  local url="$1"
  info "Downloading binary from GitHub..."

  mkdir -p "$INSTALL_DIR"
  TMP="$(mktemp)"

  if command -v curl &>/dev/null; then
    curl -fsSL "$url" -o "$TMP"
  elif command -v wget &>/dev/null; then
    wget -qO "$TMP" "$url"
  else
    error "Neither curl nor wget found. Please install one and retry."
  fi

  chmod +x "$TMP"
  mv "$TMP" "$INSTALL_DIR/$BINARY_NAME"
  success "Installed to $INSTALL_DIR/$BINARY_NAME"
}

install_via_go() {
  info "No pre-built binary for your platform. Trying 'go install'..."
  if ! command -v go &>/dev/null; then
    error "Go is not installed. Install it from https://go.dev/dl/ then re-run this script."
  fi
  go install "github.com/${REPO}@latest"
  INSTALL_DIR="$(go env GOPATH)/bin"
  success "Installed via 'go install' to $INSTALL_DIR"
}

case "$PLATFORM" in
  linux)  install_via_download "${RAW_BASE}/malcat_linux" ;;
  macos)
    warn "No macOS binary in repo yet. Falling back to 'go install'."
    install_via_go
    ;;
esac

# ── PATH setup ────────────────────────────────────────────────────────────────
add_to_path() {
  local shell_rc="$1"
  local export_line="export PATH=\"\$PATH:${INSTALL_DIR}\""

  if [ -f "$shell_rc" ] && grep -qF "$INSTALL_DIR" "$shell_rc"; then
    warn "$INSTALL_DIR already in PATH (found in $shell_rc). Skipping."
    return
  fi

  printf "\n# Added by malcat installer\n%s\n" "$export_line" >> "$shell_rc"
  info "Added $INSTALL_DIR to PATH in $shell_rc"
}

SHELL_NAME="$(basename "${SHELL:-/bin/bash}")"
case "$SHELL_NAME" in
  zsh)  add_to_path "$HOME/.zshrc" ;;
  bash) add_to_path "$HOME/.bashrc"
        [ -f "$HOME/.bash_profile" ] && add_to_path "$HOME/.bash_profile" ;;
  fish)
    mkdir -p "$HOME/.config/fish"
    FISH_LINE="set -gx PATH \$PATH $INSTALL_DIR"
    if ! grep -qF "$INSTALL_DIR" "$HOME/.config/fish/config.fish" 2>/dev/null; then
      echo "$FISH_LINE" >> "$HOME/.config/fish/config.fish"
      info "Added $INSTALL_DIR to PATH in fish config."
    fi
    ;;
  *) add_to_path "$HOME/.profile" ;;
esac

export PATH="$PATH:$INSTALL_DIR"

# ── Verify ────────────────────────────────────────────────────────────────────
echo ""
if command -v "$BINARY_NAME" &>/dev/null; then
  success "✓ '$BINARY_NAME' is ready to use!"
else
  warn "'$BINARY_NAME' not found in current shell PATH yet."
  echo "  Run: export PATH=\"\$PATH:${INSTALL_DIR}\""
  echo "  Or open a new terminal session."
fi

echo ""
echo -e "  ${CYAN}Run:${NC}  $BINARY_NAME --help"
echo -e "  ${CYAN}Tip:${NC}  Run this script again to uninstall."
echo ""