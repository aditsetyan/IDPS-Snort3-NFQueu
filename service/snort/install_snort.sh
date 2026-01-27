#!/bin/bash
# ==========================================================
#  Script   : install_snort.sh
#  Author   : Adit Setya Nugroho
#  Purpose  : Build & install Snort 3 dari source
# ==========================================================
set -e
 
cd /usr/src
sudo rm -rf snort3 || true
sudo git clone https://github.com/snort3/snort3.git
cd snort3

# No prefix → install to official /usr/local/*
sudo ./configure_cmake.sh

cd build
sudo make -j $(nproc)
sudo make install

# Verivikasi Snort
snort -V || true

# Verivikasi Daqs
snort --daq-list