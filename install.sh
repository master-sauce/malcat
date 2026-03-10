#!/usr/bin/env bash
set -e

REPO="master-sauce/malcat"
BINARY_NAME="malcat"
INSTALL_DIR="$HOME/.local/bin"
BINARY_PATH="$INSTALL_DIR/$BINARY_NAME"
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

# ── Uninstall ─────────────────────────────────────────────────────────────────
uninstall() {
  echo ""
  info "Uninstalling malcat..."

  # Remove the binary
  if [ -f "$BINARY_PATH" ]; then
    rm -f "$BINARY_PATH"
    success "Removed binary: $BINARY_PATH"
  else
    warn "Binary not found at $BINARY_PATH — already removed?"
  fi

  # Clean PATH entries from all common shell RC files
  # Removes both the comment line and any line referencing our INSTALL_DIR
  remove_from_rc() {
    local rc="$1"
    [ -f "$rc" ] || return

    # Check if our install dir is mentioned at all in the file
    if grep -qF "$INSTALL_DIR" "$rc" || grep -qF "malcat installer" "$rc"; then
      # Use a temp file for safe in-place editing (works on both Linux and macOS)
      local tmp
      tmp="$(mktemp)"
      grep -v "# Added by malcat installer" "$rc" \
        | grep -v "export PATH.*$INSTALL_DIR" \
        | grep -v "set -gx PATH.*$INSTALL_DIR" \
        > "$tmp"
      mv "$tmp" "$rc"
      success "Cleaned PATH entry from $rc"
    fi
  }

  remove_from_rc "$HOME/.bashrc"
  remove_from_rc "$HOME/.bash_profile"
  remove_from_rc "$HOME/.zshrc"
  remove_from_rc "$HOME/.profile"
  remove_from_rc "$HOME/.config/fish/config.fish"

  echo ""
  success "✓ malcat uninstalled. Open a new terminal to fully clear your PATH."
  echo ""
  exit 0
}

# ── Toggle: if already installed, prompt to uninstall ─────────────────────────
if [ -f "$BINARY_PATH" ]; then
  echo ""
  warn "malcat is already installed at $BINARY_PATH"
  printf "  ${YELLOW}Uninstall it? [y/N]:${NC} "
  read -r CONFIRM
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
  info "Downloading from: $url"

  mkdir -p "$INSTALL_DIR"
  TMP="$(mktemp)"

  if command -v curl &>/dev/null; then
    curl -fsSL "$url" -o "$TMP"
  elif command -v wget &>/dev/null; then
    wget -qO "$TMP" "$url"
  else
    error "Neither curl nor wget found. Please install one and retry."
  fi

  # Sanity check: make sure we got a binary, not an HTML error page
  local filetype
  filetype="$(file "$TMP" 2>/dev/null || echo '')"
  if echo "$filetype" | grep -qi "HTML\|text"; then
    rm -f "$TMP"
    error "Download returned an HTML page instead of a binary.\nCheck that the URL is correct: $url"
  fi

  chmod +x "$TMP"
  mv "$TMP" "$BINARY_PATH"
  success "Installed to $BINARY_PATH"
}

install_via_go() {
  info "No pre-built binary for your platform. Trying 'go install'..."
  if ! command -v go &>/dev/null; then
    error "Go is not installed. Install it from https://go.dev/dl/ then re-run this script."
  fi
  go install "github.com/${REPO}@latest"
  INSTALL_DIR="$(go env GOPATH)/bin"
  BINARY_PATH="$INSTALL_DIR/$BINARY_NAME"
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
    FISH_RC="$HOME/.config/fish/config.fish"
    if ! grep -qF "$INSTALL_DIR" "$FISH_RC" 2>/dev/null; then
      printf "\n# Added by malcat installer\nset -gx PATH \$PATH %s\n" "$INSTALL_DIR" >> "$FISH_RC"
      info "Added $INSTALL_DIR to PATH in $FISH_RC"
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