#!/bin/bash
# ==========================================================
#  Script   : install_libdaq.sh
#  Author   : Adit Setya Nugroho
#  Purpose  : Build & install libdaq untuk Snort 3
# ==========================================================
set -e
cd /usr/src
sudo rm -rf libdaq || true
sudo git clone https://github.com/snort3/libdaq.git
cd libdaq
./bootstrap
./configure
make
sudo make install
sudo ldconfig