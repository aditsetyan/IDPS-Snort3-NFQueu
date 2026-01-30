#!/bin/bash
# ==========================================================
#  Script   : install_snort.sh
#  Author   : Adit Setya Nugroho
#  Purpose  : Build & install Snort 3 dari source
# ==========================================================
set -e

# 1. Menuju direktori source (Dapur)
cd /usr/src

# 2. Bersihkan sisa-sisa lama jika ada
sudo rm -rf snort3 || true

# 3. Clone source code resmi dari GitHub
echo "[*] Mengambil source code Snort 3..."
sudo git clone https://github.com/snort3/snort3.git
cd snort3

# 4. Konfigurasi CMake (Default install ke /usr/local)
echo "[*] Mengonfigurasi CMake..."
sudo ./configure_cmake.sh

# 5. Kompilasi menggunakan semua core CPU yang tersedia
echo "[*] Memulai kompilasi (ini akan memakan waktu)..."
cd build
sudo make -j $(nproc)

# 6. Install binary ke sistem
echo "[*] Menginstal Snort ke /usr/local/bin..."
sudo make install

# 7. BERSIHKAN SOURCE CODE (Dapur Bersih)
# Agar tidak menumpuk di /usr/src dan tidak nyasar ke folder Django
echo "[*] Membersihkan folder build dan source..."
cd /usr/src
sudo rm -rf snort3

# 8. Verifikasi Hasil Instalasi
echo "=============================================="
echo "          VERIFIKASI INSTALASI SNORT          "
echo "=============================================="

# Cek versi
/usr/local/bin/snort -V || echo "Error: Snort tidak terdeteksi!"

# Cek apakah DAQ NFQ sudah terdeteksi (Penting untuk IPS Mode)
echo "[*] Mengecek dukungan DAQ (Cari 'nfq' di daftar ini):"
/usr/local/bin/snort --daq-list | grep -i nfq || echo "Warning: DAQ nfq tidak ditemukan!"

echo "=============================================="
echo "        INSTALLASI SNORT 3 SELESAI!           "
echo "=============================================="