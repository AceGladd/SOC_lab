#!/bin/sh
set -eu

CLIENT_NAME="${CLIENT_NAME:-}"

case "$CLIENT_NAME" in
    '')
        echo "CLIENT_NAME zorunludur. Ornek: -e CLIENT_NAME=employee-laptop" >&2
        exit 1
        ;;
    *[!a-zA-Z0-9_-]*)
        echo "CLIENT_NAME sadece harf, rakam, alt cizgi ve tire icerebilir." >&2
        exit 1
        ;;
esac

if [ ! -f /etc/openvpn/pki/ca.crt ]; then
    echo "PKI bulunamadi. Once normal OpenVPN servisini baslatin." >&2
    exit 1
fi

if [ -f "/etc/openvpn/pki/issued/${CLIENT_NAME}.crt" ]; then
    echo "${CLIENT_NAME} adinda bir sertifika zaten var; mevcut sertifika korunuyor." >&2
    echo "Yeni bir ad secin veya once sertifikayi iptal edin." >&2
    exit 1
fi

echo "${CLIENT_NAME} icin parolali istemci anahtari olusturuluyor."
echo "Birazdan 'Enter PEM pass phrase' satirinda parolanizi iki kez girin."
echo "Parola ekranda gorunmeyecektir ve hicbir ayar dosyasina yazilmayacaktir."

EASYRSA_BATCH=1 easyrsa build-client-full "$CLIENT_NAME"

mkdir -p /profiles
ovpn_getclient "$CLIENT_NAME" > "/profiles/${CLIENT_NAME}.ovpn"
printf '\nauth-user-pass\n' >> "/profiles/${CLIENT_NAME}.ovpn"
chmod 600 "/profiles/${CLIENT_NAME}.ovpn" 2>/dev/null || true

echo "Parolali istemci profili hazir: client_profiles/${CLIENT_NAME}.ovpn"
