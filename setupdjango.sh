#!/bin/bash
set -euo pipefail

# 1. Inisialisasi Direktori
TARGET_DIR="${TARGET_DIR:-$(pwd)}"
cd "$TARGET_DIR"
PROJECT_DIR="$(pwd)"
echo "[INFO] Project Directory: $PROJECT_DIR"

# 2. Dependencies
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip

# 3. User Service (Tetap menggunakan ubuntuserver)
DEFAULT_SERVICE_USER="$(stat -c '%U' "$PROJECT_DIR" 2>/dev/null || echo django)"
SERVICE_USER="${DJANGO_USER:-$DEFAULT_SERVICE_USER}"

# 4. Logging
sudo mkdir -p /var/log/django
sudo chown -R "$SERVICE_USER:$SERVICE_USER" /var/log/django
sudo chmod 755 /var/log/django

# 5. Setup Venv & Install Requirements
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate
pip install --upgrade pip
# Pastikan gunicorn dan whitenoise terinstal
pip install gunicorn whitenoise
pip install -r requirements.txt
python manage.py migrate
python manage.py collectstatic --noinput
deactivate

# 6. Socket Path
SOCKET_PATH="/run/${SERVICE_USER}"
sudo mkdir -p "$SOCKET_PATH"
sudo chown "$SERVICE_USER:$SERVICE_USER" "$SOCKET_PATH"

# 7. Setup Systemd Service (Ditambahkan EnvironmentFile)
echo "[INFO] Mengonfigurasi Gunicorn Service..."
sudo tee /etc/systemd/system/django.service >/dev/null <<EOF
[Unit]
Description=Firewall IDS/IPS Django Dashboard
After=network.target

[Service]
WorkingDirectory=$PROJECT_DIR
# Menggunakan path absolut venv secara eksplisit
ExecStart=$PROJECT_DIR/venv/bin/gunicorn \\
    --workers 3 \\
    --bind 0.0.0.0:8000 \\
    --chdir $PROJECT_DIR \\
    core.wsgi:application
Restart=always
RestartSec=3
User=$SERVICE_USER
Group=$SERVICE_USER
# PENTING: Agar Gunicorn membaca SECRET_KEY dari file .env
EnvironmentFile=$PROJECT_DIR/.env
Environment="DJANGO_SETTINGS_MODULE=core.settings"
StandardOutput=append:/var/log/django/access.log
StandardError=append:/var/log/django/error.log

[Install]
WantedBy=multi-user.target
EOF

# 8. Reload & Restart
sudo systemctl daemon-reload
sudo systemctl enable django.service
sudo systemctl restart django.service

# 9. Izin Log Snort
sudo mkdir -p /var/log/snort
sudo chown root:ubuntuserver /var/log/snort
sudo chmod 2770 /var/log/snort

echo "=========================================="
echo " Django Web Server (Gunicorn) Berjalan!"
echo " Cek status: sudo systemctl status django.service"
echo "=========================================="