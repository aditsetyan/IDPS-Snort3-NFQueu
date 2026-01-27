#!/bin/bash
set -euo pipefail
# ==========================================================
#  Django Web Server
#  Author : Adit Setya Nugroho (mod by Codex)
# ==========================================================

TARGET_DIR="${TARGET_DIR:-$(pwd)}"
cd "$TARGET_DIR"
PROJECT_DIR="$(pwd)"
echo "[INFO] Project Directory: $PROJECT_DIR"

sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip

# Secara default gunakan pemilik folder proyek sebagai user service,
# agar tidak ada masalah izin ketika proyek berada di $HOME pengguna.
DEFAULT_SERVICE_USER="$(stat -c '%U' "$PROJECT_DIR" 2>/dev/null || echo django)"
SERVICE_USER="${DJANGO_USER:-$DEFAULT_SERVICE_USER}"

if id "$SERVICE_USER" &>/dev/null; then
    echo "[INFO] User '$SERVICE_USER' sudah ada → skip"
else
    echo "[INFO] Membuat user '$SERVICE_USER'"
    sudo useradd -r -s /bin/false "$SERVICE_USER"
fi

sudo mkdir -p /var/log/django
sudo chown -R "$SERVICE_USER:$SERVICE_USER" /var/log/django
sudo chmod 755 /var/log/django

python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python manage.py migrate

echo "[INFO] Membuat superuser Django..."
python manage.py createsuperuser || true
deactivate

SOCKET_PATH="/run/${SERVICE_USER}"
sudo mkdir -p "$SOCKET_PATH"
sudo chown "$SERVICE_USER:$SERVICE_USER" "$SOCKET_PATH"

sudo tee /etc/systemd/system/django.service >/dev/null <<EOF
[Unit]
Description=Firewall IDS/IPS Django Dashboard
After=network.target

[Service]
WorkingDirectory=$PROJECT_DIR
ExecStart=$PROJECT_DIR/venv/bin/python $PROJECT_DIR/manage.py runserver 0.0.0.0:8000
Restart=always
User=$SERVICE_USER
Group=$SERVICE_USER
Environment="DJANGO_SETTINGS_MODULE=core.settings"

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable django.service
sudo systemctl restart django.service

sudo chown root:ubuntu /var/log/snort
sudo chown root:ubuntu /var/log/snort/*.txt
sudo chmod 2770 /var/log/snort
sudo chmod 660 /var/log/snort/*.txt
sudo systemctl restart django

echo "=========================================="
echo " Django Web Server sudah berjalan!"
echo " Dashboard → http://<server-ip>:8000"
echo "=========================================="
echo " Service Commands:"
echo "   sudo systemctl status django.service"
echo "   sudo systemctl restart django.service"
echo "   sudo systemctl stop django.service"
