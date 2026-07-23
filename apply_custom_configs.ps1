Write-Host "SOC Lab Wazuh Konfigürasyonlarını Uyguluyor..." -ForegroundColor Cyan

Write-Host "1. Manager OSSEC Konfigürasyonu Kopyalanıyor..."
docker cp ./config/manager_ossec.conf wazuh_manager:/var/ossec/etc/ossec.conf
docker exec wazuh_manager chown wazuh:wazuh /var/ossec/etc/ossec.conf
docker exec wazuh_manager chmod 660 /var/ossec/etc/ossec.conf

Write-Host "2. Agent OSSEC Konfigürasyonu Kopyalanıyor..."
docker cp ./config/ossec.conf wazuh_agent_dmz:/var/ossec/etc/ossec.conf
docker exec wazuh_agent_dmz chown wazuh:wazuh /var/ossec/etc/ossec.conf
docker exec wazuh_agent_dmz chmod 660 /var/ossec/etc/ossec.conf

Write-Host "3. Active Response (firewall-drop) Scripti Yükleniyor..."
docker cp ./config/firewall-drop wazuh_agent_dmz:/var/ossec/active-response/bin/firewall-drop
docker exec wazuh_agent_dmz chown root:wazuh /var/ossec/active-response/bin/firewall-drop
docker exec wazuh_agent_dmz chmod 750 /var/ossec/active-response/bin/firewall-drop

Write-Host "4. RADIUS (PKI/EAP-TLS) Konfigürasyon İzinleri Düzeltiliyor..."
# Not: Docker bind mount, radius_config/ klasorunun izinlerini bozabiliyor
# (ozellikle Windows'ta). FreeRADIUS bu yuzden "Permission denied" hatasi
# verip acilmayi reddedebiliyor. Bu nedenle, radius_config/ klasorunun izinlerini FreeRADIUS konteyneri icinde duzeltiyoruz. 
if (Test-Path "./radius_config") {
    docker run --rm -v "${PWD}/radius_config:/etc/freeradius" freeradius/freeradius-server:latest bash -c "
        chown -R freerad:freerad /etc/freeradius &&
        find /etc/freeradius -type d -exec chmod 750 {} \; &&
        find /etc/freeradius -type f -exec chmod 640 {} \;
    "
} else {
    Write-Host "   radius_config/ klasoru bulunamadi, bu adim atlaniyor." -ForegroundColor Yellow
}

Write-Host "5. Servisler Yeniden Başlatılıyor..."
docker restart wazuh_manager
docker restart wazuh_agent_dmz
docker compose up -d radius_server

Write-Host "Bitti! Tüm özel kurallar, Active Response ve RADIUS ayarları uygulandı." -ForegroundColor Green