#!/bin/bash
set -e

echo "=============================================="
echo "            Setup Sistem IDS & IPS            "
echo "=============================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="${TARGET_DIR:-/opt/IDPS-Snort3-NFQueu}"

# 1. Deployment Folder
if [[ "$SCRIPT_DIR" != "$TARGET_DIR" ]]; then
  echo " [+] Deploying files to $TARGET_DIR ..."
  sudo mkdir -p "$TARGET_DIR"
  sudo rsync -a --delete "$SCRIPT_DIR/" "$TARGET_DIR/"
fi

# 2. Router & Network (Infrastruktur)
echo " [+] Konfigurasi Router (Interface, NAT, DHCP)..."
# Kita simpan output interface ke variabel lingkungan sementara
source <(sudo bash "$TARGET_DIR/service/router/router.sh" | grep -E 'WAN=|LAN=')

# 3. Snort Engine (Keamanan)
echo " [+] Instalasi Dependencies, LibDAQ & Snort 3..."
sudo bash "$TARGET_DIR/service/snort/install_dependencies.sh"
sudo bash "$TARGET_DIR/service/snort/install_libdaq.sh"
sudo bash "$TARGET_DIR/service/snort/install_snort.sh"

# 4. Otomatisasi Service (PENAMBAHAN LOGIKA ANTI-SALAH INTERFACE)
echo " [+] Mengonfigurasi Snort 3 sebagai System Service..."

# Pastikan variabel WAN_IF dan LAN_IF tersedia, jika tidak, kita deteksi manual
WAN_IF="${WAN_IF:-ens33}"
LAN_IF="${LAN_IF:-ens37}"

# Modifikasi file service di folder TARGET agar sesuai dengan interface saat ini
# Ini mencegah Snort NIC bermasalah karena nama interface yang salah
sudo sed -i "s/WAN_PLACEHOLDER/$WAN_IF/g" "$TARGET_DIR/service/snort/systemd/snort-nic.service"
sudo sed -i "s/LAN_PLACEHOLDER/$LAN_IF/g" "$TARGET_DIR/service/snort/systemd/snort-nic.service"

# Menyalin file service ke folder systemd
sudo cp "$TARGET_DIR/service/snort/systemd/snort-nic.service" /etc/systemd/system/
sudo cp "$TARGET_DIR/service/snort/systemd/snort3.service" /etc/systemd/system/

sudo systemctl daemon-reload
sudo systemctl enable snort-nic.service snort3.service
sudo systemctl restart snort-nic.service snort3.service

# 5. Web Dashboard (Monitoring)
echo " [+] Konfigurasi Django..."
cd "$TARGET_DIR"
sudo bash "$TARGET_DIR/setupdjango.sh"

# 6. Permission Final
echo " [+] Mengatur izin akses log untuk Dashboard..."
sudo mkdir -p /var/log/snort
sudo touch /var/log/snort/alert_json.txt
sudo chown -R $USER:$USER /var/log/snort
sudo chmod -R 755 /var/log/snort

echo "===================== DONE ====================="
echo " Sistem siap! Jalankan simulasi serangan untuk tes."