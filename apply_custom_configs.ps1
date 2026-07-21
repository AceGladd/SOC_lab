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

Write-Host "4. Servisler Yeniden Başlatılıyor..."
docker restart wazuh_manager
docker restart wazuh_agent_dmz

Write-Host "Bitti! Tüm özel kurallar ve Active Response ayarları uygulandı." -ForegroundColor Green
