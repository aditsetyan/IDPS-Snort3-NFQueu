#!/bin/bash
set -e
echo "=============================================="
echo "            Setup Sistem IDS & IPS            "
echo "=============================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Tentukan lokasi deployment; default gunakan folder saat ini agar tidak membingungkan.
TARGET_DIR="${TARGET_DIR:-$SCRIPT_DIR}"

if [[ "$TARGET_DIR" != "$SCRIPT_DIR" ]]; then
  echo " Menyalin folder Firewall_v0 ke $TARGET_DIR ..."
  sudo mkdir -p "$TARGET_DIR"
  sudo rsync -a --delete "$SCRIPT_DIR/" "$TARGET_DIR/"
  SOURCE_DIR="$TARGET_DIR"
else
  echo " Menjalankan instalasi langsung dari $SCRIPT_DIR (tanpa menyalin ke /opt)."
  SOURCE_DIR="$SCRIPT_DIR"
fi

# Pastikan user django punya akses jika target berbeda dan user tersedia
if id django >/dev/null 2>&1; then
  sudo chown -R django:django "$TARGET_DIR"
fi

# 1. Konfigurasi router (netplan + iptables + DHCP)
echo " Menjalankan konfigurasi router..."
sudo bash "$SOURCE_DIR/service/router/router.sh"

# 2. Instalasi Snort 3
echo " Menjalankan instalasi Snort..."
sudo bash "$SOURCE_DIR/service/snort/install.sh"

# 3. Konfigurasi Django (berjalan dari folder target)
cd "$TARGET_DIR"
echo " Sekarang working directory: $(pwd)"
echo " Konfigurasi Django Web Server ..."
sudo bash "$TARGET_DIR/setupdjango.sh"

echo "===================== DONE ====================="
echo " Django Dashboard sudah dikonfigurasi!"
