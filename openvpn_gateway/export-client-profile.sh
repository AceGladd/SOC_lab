#!/bin/sh
set -eu

CLIENT_NAME="${CLIENT_NAME:-}"

case "$CLIENT_NAME" in
    '') echo "CLIENT_NAME zorunludur. Ornek: -e CLIENT_NAME=employee-laptop" >&2; exit 1 ;;
    *[!a-zA-Z0-9_-]*) echo "Gecersiz CLIENT_NAME." >&2; exit 1 ;;
esac

if [ ! -f "/etc/openvpn/pki/issued/${CLIENT_NAME}.crt" ]; then
    echo "${CLIENT_NAME} sertifikasi bulunamadi." >&2
    exit 1
fi

mkdir -p /profiles
ovpn_getclient "$CLIENT_NAME" > "/profiles/${CLIENT_NAME}.ovpn"
if ! grep -q '^auth-user-pass$' "/profiles/${CLIENT_NAME}.ovpn"; then
    printf '\nauth-user-pass\n' >> "/profiles/${CLIENT_NAME}.ovpn"
fi
chmod 600 "/profiles/${CLIENT_NAME}.ovpn" 2>/dev/null || true
echo "RADIUS kullanici girisli profil hazir: client_profiles/${CLIENT_NAME}.ovpn"
