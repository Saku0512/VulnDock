#!/usr/bin/env bash
set -euo pipefail

DIST_DIR="${1:-dist}"
REPO="${GITHUB_REPOSITORY:-Saku0512/VulnDock}"
REF_NAME="${GITHUB_REF_NAME:-${VULNDOCK_VERSION:-v0.1.0}}"
RELEASE_TAG="${VULNDOCK_RELEASE_TAG:-$REF_NAME}"
VERSION="${RELEASE_TAG#v}"
BASE_URL="https://github.com/${REPO}/releases/download/${RELEASE_TAG}"
PACKAGE_ID="Saku0512.VulnDock"
FORMULA_PATH="${DIST_DIR}/vulndock.rb"

sha256_file() {
  sha256sum "$1" | awk '{print $1}'
}

asset_url() {
  printf '%s/%s' "$BASE_URL" "$1"
}

write_formula_source() {
  local os_name="$1"
  local amd64_asset="$2"
  local arm64_asset="$3"
  local amd64_path="${DIST_DIR}/${amd64_asset}"
  local arm64_path="${DIST_DIR}/${arm64_asset}"

  if [ -f "$amd64_path" ] && [ -f "$arm64_path" ]; then
    cat <<FORMULA
  if OS.${os_name}? && Hardware::CPU.arm?
    url "$(asset_url "$arm64_asset")"
    sha256 "$(sha256_file "$arm64_path")"
  elsif OS.${os_name}?
    url "$(asset_url "$amd64_asset")"
    sha256 "$(sha256_file "$amd64_path")"
  end
FORMULA
  elif [ -f "$arm64_path" ]; then
    cat <<FORMULA
  if OS.${os_name}? && Hardware::CPU.arm?
    url "$(asset_url "$arm64_asset")"
    sha256 "$(sha256_file "$arm64_path")"
  end
FORMULA
  elif [ -f "$amd64_path" ]; then
    cat <<FORMULA
  if OS.${os_name}? && !Hardware::CPU.arm?
    url "$(asset_url "$amd64_asset")"
    sha256 "$(sha256_file "$amd64_path")"
  end
FORMULA
  fi
}

write_homebrew_formula() {
  local darwin_source
  local linux_source

  darwin_source="$(write_formula_source mac "VulnDock_darwin_amd64.zip" "VulnDock_darwin_arm64.zip")"
  linux_source="$(write_formula_source linux "VulnDock_linux_amd64.tar.gz" "VulnDock_linux_arm64.tar.gz")"

  if [ -z "$darwin_source" ] && [ -z "$linux_source" ]; then
    printf 'No Homebrew-compatible release assets found in %s\n' "$DIST_DIR" >&2
    return
  fi

  cat > "$FORMULA_PATH" <<FORMULA
class Vulndock < Formula
  desc "Desktop app for organizing vulnerability report metadata and PoC attachments"
  homepage "https://github.com/${REPO}"
  version "${VERSION}"
  license "MIT"

${darwin_source}
${linux_source}

  def install
    if OS.mac?
      prefix.install "VulnDock.app"
      bin.write_exec_script prefix/"VulnDock.app/Contents/MacOS/VulnDock"
    else
      bin.install "VulnDock"
      pkgshare.install "vulndock.desktop" if File.exist?("vulndock.desktop")
      pkgshare.install "vulndock.png" if File.exist?("vulndock.png")
    end
  end

  test do
    assert_predicate bin/"VulnDock", :exist?
  end
end
FORMULA
}

write_winget_manifests() {
  local windows_asset="VulnDock_windows_amd64.zip"
  local windows_path="${DIST_DIR}/${windows_asset}"
  local manifest_dir="${DIST_DIR}/winget-manifests/manifests/s/Saku0512/VulnDock/${VERSION}"
  local bundle_path="${DIST_DIR}/VulnDock_winget_${VERSION}.zip"

  if [ ! -f "$windows_path" ]; then
    printf 'No Windows release asset found at %s\n' "$windows_path" >&2
    return
  fi

  mkdir -p "$manifest_dir"

  cat > "${manifest_dir}/${PACKAGE_ID}.yaml" <<YAML
PackageIdentifier: ${PACKAGE_ID}
PackageVersion: ${VERSION}
DefaultLocale: en-US
ManifestType: version
ManifestVersion: 1.9.0
YAML

  cat > "${manifest_dir}/${PACKAGE_ID}.installer.yaml" <<YAML
PackageIdentifier: ${PACKAGE_ID}
PackageVersion: ${VERSION}
InstallerType: zip
NestedInstallerType: portable
NestedInstallerFiles:
  - RelativeFilePath: VulnDock.exe
    PortableCommandAlias: VulnDock
Installers:
  - Architecture: x64
    InstallerUrl: $(asset_url "$windows_asset")
    InstallerSha256: $(sha256_file "$windows_path")
ManifestType: installer
ManifestVersion: 1.9.0
YAML

  cat > "${manifest_dir}/${PACKAGE_ID}.locale.en-US.yaml" <<YAML
PackageIdentifier: ${PACKAGE_ID}
PackageVersion: ${VERSION}
PackageLocale: en-US
Publisher: Saku0512
PackageName: VulnDock
ShortDescription: Desktop app for organizing vulnerability report metadata and PoC attachments.
PackageUrl: https://github.com/${REPO}
License: MIT
LicenseUrl: https://github.com/${REPO}/blob/main/LICENSE
ManifestType: defaultLocale
ManifestVersion: 1.9.0
YAML

  (
    cd "${DIST_DIR}/winget-manifests"
    zip -qr "../$(basename "$bundle_path")" manifests
  )
}

write_homebrew_formula
write_winget_manifests
