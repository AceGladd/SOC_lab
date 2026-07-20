# Segmented NAC & SOC Lab Infrastructure

## Proje Özeti

Aşağıda bulunan mimari şemada görüldüğü üzere bu proje, Docker Compose kullanılarak inşa edilmiş, bölümlendirilmiş (Segmented) bir Ağ Erişim Kontrolü (NAC) ve Güvenlik Operasyon Merkezi (SOC) laboratuvar ortamıdır.

<img src="system architecture diagram.png" alt="Sistem Mimarisi" width="700">

Altyapımız yapısal olarak iki yalıtılmış ağdan (DMZ ve İç Ağ) ve iki temel akıştan oluşmaktadır:

1. **Ağ Erişim Kontrolü (NAC):** Dış kullanıcılar öncelikle VPN üzerinden (DMZ) İç Ağ'daki Radius sunucusuna ulaşır. Radius, özel Politik Motoruna (FastAPI) danışır. Veritabanı (PostgreSQL) ve Hız Sınırlandırma (Redis) kontrolleri sonrası kullanıcıların ağa erişimi onaylanır veya reddedilir.
2. **Güvenlik Operasyon Merkezi (SOC):** Uygulama logları ve şüpheli aktiviteler, ağlar arasında köprü kuran Ajan (Wazuh Agent) üzerinden toplanarak İç Ağ'daki SIEM merkezine (Wazuh Manager) güvenli bir şekilde aktarılır ve otomatik tehdit müdahalesi (Active Response) süreçleri işletilir.

## Ön Koşullar

Bu laboratuvarı kendi bilgisayarınızda çalıştırmak için yalnızca aşağıdaki araçların kurulu olması gerekmektedir:

- **Docker**
- **Docker Compose**

## Başlangıç

Tüm altyapıyı ayağa kaldırmak ve konteynerleri başlatmak için projenin kök dizininde aşağıdaki komutu çalıştırmanız yeterlidir:

```bash
docker compose up -d --build
```

_(Not: Ortamı ilk kez ayağa kaldırmadan önce FreeRADIUS varsayılan yapılandırmalarının ve OpenVPN PKI sertifikalarının başlatılmış olduğundan emin olun.)_

## Ağ Mimarisi

Güvenlik prensipleri gereği servisler iki farklı izole ağa dağıtılmıştır:

- **DMZ Ağı (`dmz_net`)**: Dışarıdan erişime açık olan veya test hedeflerini barındıran servisler.
  - `vpn_gateway` (OpenVPN - Hem DMZ hem de İç Ağa bağlıdır)
  - `dummy_web` (Nginx - Test hedefi)

- **İç Ağ (`internal_net`)**: Yalnızca VPN veya diğer iç servisler üzerinden erişilebilen, dışarıya kapalı kritik servisler.
  - `db_postgres` (Veritabanı)
  - `cache_redis` (Önbellek)
  - `radius_server` (FreeRADIUS)
  - `policy_engine` (FastAPI)
  - `wazuh_manager` (Wazuh SIEM)

## Servislere Erişim ve Etkileşim

Servislerle etkileşime geçmek, arayüzlerine ulaşmak ve hata ayıklamak için aşağıdaki yöntemleri kullanabilirsiniz:

- **Wazuh Arayüzü (UI)**: Tarayıcınızdan [https://localhost:443](https://localhost:443) adresine giderek erişebilirsiniz.
- **FastAPI (Policy Engine)**: Güvenlik prensipleri gereği Policy Engine arayüzü (Port 8000) kasıtlı olarak host makineye (dışarıya) **açılmamıştır**. Yalnızca iç ağ üzerinden diğer konteynerlerin içinden test edilebilir (örn: `curl http://policy_engine:8000`).
- **Konteyner İçine Girme**: Herhangi bir servisin içine girip komut çalıştırmak için:
  ```bash
  docker exec -it <container_name> bash
  ```
  _(Alpine tabanlı imajlarda `bash` yerine `sh` kullanmanız gerekebilir.)_
- **Logları Görüntüleme**: Servislerin canlı loglarını takip etmek için:
  ```bash
  docker logs -f <container_name>
  ```

## Sonraki Adımlar ve Görev Dağılımı

Aşağıdaki liste, laboratuvarın geri kalan kısımları için (Phase 2 & Phase 3 Red/Blue Team senaryoları dahil) ekibin görev dağılımını içermektedir:

- **Bedirhan İhtiyar (Kaptan)**: Wazuh ajanlarının entegrasyonu, Redis Rate-Limiting mantığının entegrasyonu, Phase 3 Active-Response (iptables playbook) senaryolarının uygulanması, günlük raporlamalar ve projenin nihai mimari dokümantasyonunun hazırlanması.

- **Yağız Eren Kotan**: FastAPI (Policy Engine) uç noktalarının geliştirilmesi, PostgreSQL entegrasyonu ve dinamik kural motoru (rule engine) mantığının kurgulanması.

- **Devran Baştemur**: OpenVPN gateway yapılandırması VE Phase 2 (Red Team) Senaryolarının yürütülmesi (geçersiz sertifikaların test edilmesi, Python/radclient ile brute-force saldırıları ve DMZ'den İç Ağa network segmentasyonunun test edilmesi).

- **Ömer Faruk Sevim**: FreeRADIUS (EAP-TLS) yapılandırması, istemci (client) sertifikalarının yönetimi ve Policy Engine ile `rlm_rest` modülü üzerinden haberleşmenin sağlanması.