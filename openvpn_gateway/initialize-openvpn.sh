#!/bin/sh
set -eu

VPN_SERVER_ADDRESS="${VPN_SERVER_ADDRESS:-localhost}"
VPN_PORT="${VPN_PORT:-1194}"

if [ ! -f /etc/openvpn/openvpn.conf ]; then
    echo "[1/2] OpenVPN sunucu yapilandirmasi uretiliyor..."
    ovpn_genconfig -u "udp://${VPN_SERVER_ADDRESS}:${VPN_PORT}"
else
    echo "[1/2] Mevcut sunucu yapilandirmasi korunuyor."
fi

if [ ! -f /etc/openvpn/pki/ca.crt ]; then
    echo "[2/2] CA ve sunucu sertifikalari uretiliyor..."
    EASYRSA_BATCH=1 EASYRSA_REQ_CN=SOC-Lab-CA ovpn_initpki nopass
else
    echo "[2/2] Mevcut PKI korunuyor."
fi

echo "OpenVPN sunucusu hazir. Istemciler vpn_client_create araci ile ayrica uretilir."
