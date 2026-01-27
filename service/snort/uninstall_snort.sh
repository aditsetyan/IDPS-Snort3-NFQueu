#!/bin/bash
# ==========================================================
#  Script   : uninstall_snort.sh
#  Author   : (isi sesuai nama Anda)
#  Purpose  : Menghapus Snort 3, libdaq, dan dependensi pendukung
# ==========================================================
set -euo pipefail

echo "=============================================="
echo "  Uninstall Snort 3, LibDAQ, dependensi"
echo "=============================================="

read -p "Lanjutkan proses uninstall? (y/N): " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "Dibatalkan."
    exit 0
fi

# 1. Hentikan service Snort dan hapus unit
if systemctl list-unit-files | grep -q '^snort3.service'; then
    sudo systemctl stop snort3.service 2>/dev/null || true
    sudo systemctl disable snort3.service 2>/dev/null || true
    sudo rm -f /etc/systemd/system/snort3.service
fi
if systemctl list-unit-files | grep -q '^snort3-nic.service'; then
    sudo systemctl stop snort3-nic.service 2>/dev/null || true
    sudo systemctl disable snort3-nic.service 2>/dev/null || true
    sudo rm -f /etc/systemd/system/snort3-nic.service
fi
sudo systemctl daemon-reload

echo "[1/6] Service Snort dinonaktifkan."

# 2. Hapus direktori Snort (konfig, log, plugin)
sudo rm -rf /usr/local/etc/snort /usr/local/lib/snort_extra /var/log/snort
sudo rm -rf /usr/local/etc/lists

echo "[2/6] Direktori Snort dibersihkan."

# 3. Hapus libdaq
if [[ -d /usr/src/libdaq ]]; then
    sudo rm -rf /usr/src/libdaq
fi
sudo rm -rf /usr/local/lib/daq /usr/local/include/daq
sudo rm -f /usr/local/lib/pkgconfig/libdaq*.pc
sudo ldconfig

echo "[3/6] LibDAQ dihapus."

# 4. Hapus binary Snort
sudo rm -f /usr/local/bin/snort /usr/local/bin/snort* /usr/local/lib/pkgconfig/snort*.pc

echo "[4/6] Binary Snort dibersihkan."

# 5. Opsional: uninstall paket dependensi
read -p "Hapus paket dependensi (apt remove)? (y/N): " remove_pkg
if [[ "$remove_pkg" =~ ^[Yy]$ ]]; then
    sudo apt-get remove --purge -y \
        build-essential cmake pkgconf libdumbnet-dev libpcap-dev \
        libpcre2-dev libhwloc-dev libluajit-5.1-dev luajit zlib1g-dev \
        openssl libssl-dev flex bison git autoconf libtool liblzma-dev uuid-dev
    sudo apt-get autoremove -y
    echo "[5/6] Paket dependensi dihapus."
else
    echo "[5/6] Paket dependensi dibiarkan sesuai permintaan."
fi

# 6. Hapus user snort (jika dibuat)
if id snort &>/dev/null; then
    sudo userdel -r snort 2>/dev/null || true
fi
if getent group snort >/dev/null; then
    sudo groupdel snort 2>/dev/null || true
fi

echo "[6/6] User/group snort dibersihkan."

echo "=============================================="
echo "  Snort 3 dan komponennya berhasil dihapus"
echo "=============================================="
