# OpenVPN Gateway

Bu klasor, OpenVPN gateway servisini projenin diger servislerinden bagimsiz
olarak kurup test edebilmek icin ayrilmistir.

## Dosyalar

- `Dockerfile`: Kylemanna/OpenVPN tabanli yerel laboratuvar imaji.
- `compose.yml`: Ilk kurulumu yapar ve VPN gateway servisini baslatir.
- `initialize-openvpn.sh`: Konteyner icinde ayarlari ve sertifikalari uretir.

Sertifikalar ve sunucu ayarlari `vpn_data` adli Docker volume'unda tutulur.
Ozel anahtar iceren istemci profilleri `client_profiles` altina yazilir ve
Git tarafindan yok sayilir.

## Calistirma

Terminali bu klasorde acip tek komut calistirin:

```text
docker compose up -d --build
```

Compose once `vpn_initializer` konteynerini calistirir. Bu konteyner eksikse
sunucu ayarlarini, CA'yi ve sunucu sertifikasini uretir. Istemci profilleri
guvenlik nedeniyle ayrica ve acik bir isim verilerek uretilir. Islem basarili
olduktan sonra `vpn_gateway` baslar.
Komut tekrar calistirildiginda mevcut sertifikalar silinmez.

Uzak bir bilgisayardan baglanilacaksa `localhost` yerine Docker hostunun
erisilebilir IP adresi veya alan adi kullanilmalidir. Modem/NAT arkasinda
calisiliyorsa UDP 1194 port yonlendirmesi de gerekir.

## Parolali istemci profili

Temel baglanti dogrulandiktan sonra parolali bir istemci profili olusturmak
icin su komut calistirilir:

```text
docker compose --profile tools run --rm -e CLIENT_NAME=employee-laptop vpn_client_create
```

Terminal `Enter PEM pass phrase` ve ardindan dogrulama parolasini sorar.
Parola ekranda gorunmez ve Compose dosyasina kaydedilmez. Olusan profil
`client_profiles/employee-laptop.ovpn` yoluna yazilir. Bu profil OpenVPN
Connect'e aktarildiginda baglanti sirasinda Private Key Password sorulur.

Bir istemci sertifikasini iptal etmek icin adi acikca verilir:

```text
docker compose --profile tools run --rm -e CLIENT_NAME=employee-laptop vpn_client_revoke
docker compose restart vpn_gateway
```

Iptalden sonra ilgili `.ovpn` profili VPN'e baglanamaz.

Farkli bir adres veya istemci adi icin klasorde `.env` olusturulabilir:

```dotenv
VPN_SERVER_ADDRESS=192.168.1.50
VPN_PORT=1194
```

## Durdurma

```text
docker compose down
```

Bu komut `vpn_data` volume'unu silmez; sertifikalar korunur.

## Temel segmentasyon testi

VPN istemcisine yalnizca DMZ test web servisine giden route verilir. Gateway
firewall'i `10.10.10.0/24` icinde yalnizca TCP 8080'e izin verir ve tunelden
gelen diger yonlendirilmis trafigi engeller.

VPN'e baglandiktan sonra izinli test:

```text
http://10.10.10.10:8080
```

Internal agdaki test servisi engellenmelidir:

```text
http://10.10.20.10
```

Bu temel default-deny politikasidir. Tam proje Compose'unda kurallar
RADIUS'tan donen role gore dinamik uygulanir.

## RADIUS entegrasyonu

Tam proje Compose'u `RADIUS_ENABLED=true` ile OpenVPN kullanici
dogrulamasini etkinlestirir. OpenVPN sertifikasi cihaz kimligini, RADIUS
kullanici adi/parolasi ise kullaniciyi dogrular.

FreeRADIUS `Access-Accept` cevabindaki `Tunnel-Private-Group-Id` degeri
firewall profiline cevrilir:

- VLAN 10 (`admin`): DMZ ve internal aga erisim
- VLAN 20 (`employee`): DMZ web servisi TCP 8080
- VLAN 30 (`guest`): DMZ/internal dogrudan erisim yok

Mevcut bir sertifikanin profilini kullanici adi/parola soracak sekilde tekrar
disari aktarmak icin:

```text
docker compose --profile tools run --rm -e CLIENT_NAME=employee-laptop vpn_client_export
```

OpenVPN olaylari `/var/log/shared/openvpn.log`, RADIUS kabul/ret olaylari ise
JSON olarak `/var/log/shared/openvpn-radius.log` dosyasina yazilir. Ana
Compose'taki Wazuh agent ayni `shared_logs` volume'u uzerinden bu dosyalari
okur.
