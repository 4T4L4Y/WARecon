#!/bin/sh
# ProjectDiscovery CLI araçlarını GitHub release zip'lerinden kurar (go install yerine).
set -eu

DEST="${1:-/usr/local/bin}"
ARCH="${TARGETARCH:-amd64}"

case "$ARCH" in
  amd64) PD_ARCH=amd64 ;;
  arm64) PD_ARCH=arm64 ;;
  *)
    echo "Desteklenmeyen mimari: $ARCH" >&2
    exit 1
    ;;
esac

install_tool() {
  name="$1"
  version="$2"
  repo="$3"
  zip="${name}_${version}_linux_${PD_ARCH}.zip"
  url="https://github.com/projectdiscovery/${repo}/releases/download/v${version}/${zip}"
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' EXIT INT TERM

  echo ">> ${name} v${version} (${PD_ARCH})"
  curl -fsSL "$url" -o "${tmpdir}/${zip}"
  unzip -q "${tmpdir}/${zip}" -d "$tmpdir"
  install -m 0755 "${tmpdir}/${name}" "${DEST}/${name}"
  rm -rf "$tmpdir"
  trap - EXIT INT TERM
}

install_tool naabu 2.6.1 naabu
install_tool subfinder 2.14.0 subfinder
install_tool dnsx 1.2.3 dnsx
install_tool httpx 1.9.0 httpx
install_tool katana 1.6.1 katana
install_tool nuclei 3.9.0 nuclei

echo "ProjectDiscovery araçları kuruldu: $(ls -1 "$DEST" | tr '\n' ' ')"
