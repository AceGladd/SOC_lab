#!/bin/sh
set -eu

CLIENT_NAME="${CLIENT_NAME:-}"

case "$CLIENT_NAME" in
    '') echo "CLIENT_NAME zorunludur. Ornek: -e CLIENT_NAME=employee-laptop" >&2; exit 1 ;;
    *[!a-zA-Z0-9_-]*) echo "Gecersiz CLIENT_NAME." >&2; exit 1 ;;
esac

if [ ! -f "/etc/openvpn/pki/issued/${CLIENT_NAME}.crt" ]; then
    echo "${CLIENT_NAME} aktif sertifikasi bulunamadi; daha once iptal edilmis olabilir."
    exit 0
fi

echo "${CLIENT_NAME} sertifikasi iptal ediliyor..."
EASYRSA_BATCH=1 ovpn_revokeclient "$CLIENT_NAME" remove
echo "${CLIENT_NAME} iptal edildi ve yeni CRL olusturuldu."
