-- =============================================================================
-- NAC Veritabanı Başlangıç Şeması
-- Devran Baştemur – Policy Engine
-- =============================================================================
-- Bu dosya PostgreSQL konteynerinin ilk ayağa kalkışında
-- docker-entrypoint-initdb.d/ altına mount edilerek otomatik çalıştırılır.
-- =============================================================================


-- -----------------------------------------------------------------------------
-- 1. ROLES tablosu
--    Sistemdeki rol tanımları ve her rolün alabileceği VLAN + erişim profili.
--    Kural motoru bu tabloyu referans alarak dinamik karar üretir.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS roles (
    id              SERIAL      PRIMARY KEY,
    role_name       VARCHAR(32) UNIQUE NOT NULL,
    vlan_id         SMALLINT    NOT NULL,
    access_profile  VARCHAR(64) NOT NULL,
    description     TEXT,
    created_at      TIMESTAMP   NOT NULL DEFAULT NOW()
);

-- Roller ve VLAN atamaları
INSERT INTO roles (role_name, vlan_id, access_profile, description) VALUES
    ('admin',    10, 'full_access',    'Tam yetki – tüm iç ağ kaynaklarına erişim'),
    ('employee', 20, 'limited_access', 'Kısıtlı erişim – yalnızca iş uygulamaları'),
    ('guest',    30, 'internet_only',  'Misafir – yalnızca İnternet erişimi')
ON CONFLICT (role_name) DO NOTHING;


-- -----------------------------------------------------------------------------
-- 2. PERMISSIONS tablosu
--    Her rolün hangi ağ kaynaklarına (hedef, port, protokol) erişebildiğini
--    tanımlar. Kural motoru bu tabloyu genişletilmiş kontrol için kullanır.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS permissions (
    id          SERIAL      PRIMARY KEY,
    role_name   VARCHAR(32) NOT NULL REFERENCES roles(role_name) ON DELETE CASCADE,
    resource    VARCHAR(128) NOT NULL,   -- Erişime izin verilen hedef (IP/CIDR/servis adı)
    port        INTEGER,                 -- NULL → tüm portlar
    protocol    VARCHAR(10) DEFAULT 'any',
    allowed     BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMP   NOT NULL DEFAULT NOW()
);

-- admin: her şeye erişebilir
INSERT INTO permissions (role_name, resource, port, protocol, allowed) VALUES
    ('admin', '0.0.0.0/0',           NULL, 'any',  TRUE)
ON CONFLICT DO NOTHING;

-- employee: iç iş uygulamaları + İnternet (80/443), DB'ye erişim yok
INSERT INTO permissions (role_name, resource, port, protocol, allowed) VALUES
    ('employee', '10.0.0.0/8',        443,  'tcp',  TRUE),
    ('employee', '10.0.0.0/8',        80,   'tcp',  TRUE),
    ('employee', '0.0.0.0/0',         443,  'tcp',  TRUE),
    ('employee', '0.0.0.0/0',         80,   'tcp',  TRUE),
    ('employee', 'db_postgres',        5432, 'tcp',  FALSE)  -- DB'ye direkt erişim yasak
ON CONFLICT DO NOTHING;

-- guest: yalnızca İnternet HTTP/HTTPS
INSERT INTO permissions (role_name, resource, port, protocol, allowed) VALUES
    ('guest', '0.0.0.0/0', 80,  'tcp', TRUE),
    ('guest', '0.0.0.0/0', 443, 'tcp', TRUE)
ON CONFLICT DO NOTHING;


-- -----------------------------------------------------------------------------
-- 3. USERS tablosu
--    Kimlik doğrulama için referans alınan kullanıcı kayıtları.
--    role sütunu → roles tablosuna foreign key.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id          SERIAL      PRIMARY KEY,
    username    VARCHAR(64) UNIQUE NOT NULL,
    role        VARCHAR(32) NOT NULL REFERENCES roles(role_name),
    active      BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMP   NOT NULL DEFAULT NOW()
);

-- Lab ortamı için örnek kullanıcılar
INSERT INTO users (username, role, active) VALUES
    ('admin',        'admin',    TRUE),
    ('alice',        'employee', TRUE),
    ('bob',          'employee', TRUE),
    ('charlie',      'guest',    TRUE),
    ('disabled_usr', 'employee', FALSE)   -- REJECT senaryosu – devre dışı hesap
ON CONFLICT (username) DO NOTHING;


-- -----------------------------------------------------------------------------
-- 4. ACCESS_LOGS tablosu
--    Her yetkilendirme kararı (ACCEPT/REJECT) burada kalıcı olarak saklanır.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS access_logs (
    id          SERIAL       PRIMARY KEY,
    username    VARCHAR(64)  NOT NULL,
    src_ip      VARCHAR(45)  NOT NULL,   -- IPv6 desteği için 45 karakter
    decision    VARCHAR(10)  NOT NULL,   -- 'ACCEPT' veya 'REJECT'
    vlan        SMALLINT,                -- NULL → erişim reddedildi
    profile     VARCHAR(64),             -- Atanan erişim profili
    detail      TEXT,
    created_at  TIMESTAMP    NOT NULL DEFAULT NOW()
);

-- Sık sorgulanan sütunlara performans indeksleri
CREATE INDEX IF NOT EXISTS idx_logs_username   ON access_logs (username);
CREATE INDEX IF NOT EXISTS idx_logs_src_ip     ON access_logs (src_ip);
CREATE INDEX IF NOT EXISTS idx_logs_decision   ON access_logs (decision);
CREATE INDEX IF NOT EXISTS idx_logs_created_at ON access_logs (created_at DESC);
