#!/usr/bin/env sh
set -eu

APP_NAME="VulnDock"
APP_ID="vulndock"
REPO="${VULNDOCK_REPO:-Saku0512/VulnDock}"
VERSION="${VULNDOCK_VERSION:-latest}"
INSTALL_DIR="${VULNDOCK_INSTALL_DIR:-$HOME/.local/bin}"
DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
APPLICATIONS_DIR="$DATA_HOME/applications"
ICON_DIR="$DATA_HOME/icons/hicolor/256x256/apps"

log() {
  printf '%s\n' "$*"
}

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

detect_arch() {
  case "$(uname -m)" in
    x86_64 | amd64) printf 'amd64' ;;
    aarch64 | arm64) printf 'arm64' ;;
    *) fail "unsupported architecture: $(uname -m)" ;;
  esac
}

download() {
  url="$1"
  dest="$2"

  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$dest"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$dest" "$url"
  else
    fail "missing required command: curl or wget"
  fi
}

release_base_url() {
  if [ "$VERSION" = "latest" ]; then
    printf 'https://github.com/%s/releases/latest/download' "$REPO"
  else
    printf 'https://github.com/%s/releases/download/%s' "$REPO" "$VERSION"
  fi
}

install_linux() {
  need tar

  arch="$(detect_arch)"
  asset="${APP_NAME}_linux_${arch}.tar.gz"
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' EXIT HUP INT TERM

  url="$(release_base_url)/$asset"
  archive="$tmpdir/$asset"

  log "Downloading $url"
  download "$url" "$archive"

  tar -xzf "$archive" -C "$tmpdir"
  [ -f "$tmpdir/$APP_NAME" ] || fail "release archive did not contain $APP_NAME"

  mkdir -p "$INSTALL_DIR" "$APPLICATIONS_DIR" "$ICON_DIR"
  install -m 0755 "$tmpdir/$APP_NAME" "$INSTALL_DIR/$APP_NAME"

  if [ -f "$tmpdir/$APP_ID.png" ]; then
    install -m 0644 "$tmpdir/$APP_ID.png" "$ICON_DIR/$APP_ID.png"
  fi

  cat > "$APPLICATIONS_DIR/$APP_ID.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=$APP_NAME
Comment=Organize vulnerability reports and PoC attachments
Exec=$INSTALL_DIR/$APP_NAME
Icon=$APP_ID
Terminal=false
Categories=Development;Security;Utility;
StartupNotify=true
EOF

  chmod 0644 "$APPLICATIONS_DIR/$APP_ID.desktop"

  if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$APPLICATIONS_DIR" >/dev/null 2>&1 || true
  fi

  log "$APP_NAME installed to $INSTALL_DIR/$APP_NAME"
  case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *) log "Add $INSTALL_DIR to PATH if you want to launch $APP_NAME from a terminal." ;;
  esac
}

install_macos() {
  need unzip

  arch="$(detect_arch)"
  asset="${APP_NAME}_darwin_${arch}.zip"
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' EXIT HUP INT TERM

  url="$(release_base_url)/$asset"
  archive="$tmpdir/$asset"
  target_dir="${VULNDOCK_MACOS_APP_DIR:-$HOME/Applications}"

  log "Downloading $url"
  download "$url" "$archive"

  unzip -q "$archive" -d "$tmpdir"
  [ -d "$tmpdir/$APP_NAME.app" ] || fail "release archive did not contain $APP_NAME.app"

  mkdir -p "$target_dir"
  rm -rf "$target_dir/$APP_NAME.app"
  mv "$tmpdir/$APP_NAME.app" "$target_dir/$APP_NAME.app"

  log "$APP_NAME installed to $target_dir/$APP_NAME.app"
}

case "$(uname -s)" in
  Linux) install_linux ;;
  Darwin) install_macos ;;
  *) fail "unsupported OS: $(uname -s). Download a release asset from https://github.com/$REPO/releases instead." ;;
esac
