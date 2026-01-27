#!/bin/bash
# ==========================================================
#  Script   : install_dependencies.sh
#  Author   : Adit Setya N
#  Purpose  : Menginstal seluruh paket dasar/opsional
#             yang dibutuhkan untuk membangun Snort 3
# ==========================================================
set -e
sudo apt update && sudo apt upgrade -y
sudo apt install -y \
    build-essential \
    cmake \
    pkgconf \
    libdumbnet-dev \
    libpcap-dev \
    libpcre2-dev \
    libhwloc-dev \
    libluajit-5.1-dev \
    luajit \
    zlib1g-dev \
    openssl \
    libssl-dev \
    flex \
    bison \
    git \
    autoconf \
    libtool \
    liblzma-dev \
    uuid-dev
