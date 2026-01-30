#!/bin/bash
# ==========================================================
#  Script   : install_libdaq.sh
#  Author   : Adit Setya Nugroho
#  Purpose  : Build & install libdaq untuk Snort 3
# ==========================================================
set -e

cd /usr/src
# Hapus jika folder lama masih ada
sudo rm -rf libdaq || true

echo "[*] Cloning libdaq..."
sudo git clone https://github.com/snort3/libdaq.git
cd libdaq

echo "[*] Configuring & Compiling..."
sudo ./bootstrap
sudo ./configure
sudo make
sudo make install

# Bersihkan source code setelah install agar tidak menumpuk di /usr/src
cd /usr/src
sudo rm -rf libdaq

# Update cache library agar Snort bisa menemukan libdaq
sudo ldconfig

echo "[*] libdaq installed successfully."