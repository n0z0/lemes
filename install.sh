#!/usr/bin/env bash
#
# lemes Honeybeacon Installer / Upgrader for Linux
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/n0z0/lemes/main/install.sh | bash
#   atau
#   ./install.sh [version]
#
set -euo pipefail

REPO="n0z0/lemes"
VERSION="${1:-latest}"
INSTALL_DIR="/usr/local/bin"

USE_SUDO=false
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    USE_SUDO=true
  else
    INSTALL_DIR="${HOME}/.local/bin"
  fi
fi

echo "=========================================="
echo " lemes Honeybeacon Installer (Linux)      "
echo "=========================================="

ARCH="$(uname -m)"
case "${ARCH}" in
  x86_64|amd64) TARGET_ARCH="amd64" ;;
  aarch64|arm64) TARGET_ARCH="arm64" ;;
  *)
    echo "[!] Arsitektur ${ARCH} tidak didukung secara otomatis."
    exit 1
    ;;
esac

if [ "${VERSION}" = "latest" ]; then
  echo "[*] Memeriksa rilis terbaru dari GitHub..."
  TARGET_TAG=$(curl -sSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
  if [ -z "${TARGET_TAG}" ]; then
    echo "[!] Gagal mendapatkan tag rilis terbaru dari GitHub."
    exit 1
  fi
else
  case "${VERSION}" in
    v*) TARGET_TAG="${VERSION}" ;;
    *)  TARGET_TAG="v${VERSION}" ;;
  esac
fi

echo "[*] Target versi: ${TARGET_TAG} (linux/${TARGET_ARCH})"

# Cek versi terpasang
EXISTING_BIN="$(command -v lemes 2>/dev/null || true)"
if [ -n "${EXISTING_BIN}" ]; then
  CURRENT_VER="$(${EXISTING_BIN} -version 2>/dev/null || echo "unknown")"
  echo "[*] Versi terpasang saat ini: ${CURRENT_VER}"
  if [[ "${CURRENT_VER}" == *"${TARGET_TAG}"* ]]; then
    echo "[OK] lemes sudah versi terbaru (${TARGET_TAG})."
    exit 0
  fi
fi

# Buat direktori instalasi
if [ "${USE_SUDO}" = true ]; then
  sudo mkdir -p "${INSTALL_DIR}"
else
  mkdir -p "${INSTALL_DIR}"
fi

TARGET_BIN="${INSTALL_DIR}/lemes"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

DIRECT_URL="https://github.com/${REPO}/releases/download/${TARGET_TAG}/lemes_linux_${TARGET_ARCH}"
TAR_URL="https://github.com/${REPO}/releases/download/${TARGET_TAG}/lemes_${TARGET_TAG}_linux_${TARGET_ARCH}.tar.gz"

echo "[*] Mengunduh binary langsung dari ${DIRECT_URL}..."
if curl -fsSL "${DIRECT_URL}" -o "${TMP_DIR}/lemes" 2>/dev/null; then
  chmod +x "${TMP_DIR}/lemes"
else
  echo "[*] Binary langsung tidak tersedia, mencoba arsip tar.gz..."
  curl -fsSL "${TAR_URL}" -o "${TMP_DIR}/pkg.tar.gz"
  tar -xzf "${TMP_DIR}/pkg.tar.gz" -C "${TMP_DIR}"
  EXTRACTED="$(find "${TMP_DIR}" -type f -name "lemes" | head -n1)"
  mv "${EXTRACTED}" "${TMP_DIR}/lemes"
  chmod +x "${TMP_DIR}/lemes"
fi

echo "[*] Memasang ke ${TARGET_BIN}..."
if [ "${USE_SUDO}" = true ]; then
  sudo mv "${TMP_DIR}/lemes" "${TARGET_BIN}"
  sudo chmod +x "${TARGET_BIN}"
else
  mv "${TMP_DIR}/lemes" "${TARGET_BIN}"
  chmod +x "${TARGET_BIN}"
fi

# Cek PATH
if [[ ":${PATH}:" != *":${INSTALL_DIR}:"* ]]; then
  echo "[!] Peringatan: ${INSTALL_DIR} belum ada di PATH Anda."
  echo "    Tambahkan baris ini ke ~/.bashrc atau ~/.zshrc:"
  echo "    export PATH=\"${INSTALL_DIR}:\$PATH\""
fi

echo "=========================================="
echo " Sukses! lemes Honeybeacon terpasang."
echo " Versi : ${TARGET_TAG}"
echo " Lokasi: ${TARGET_BIN}"
echo "=========================================="
echo "Jalankan dengan perintah:"
echo "   lemes -port :8080"
