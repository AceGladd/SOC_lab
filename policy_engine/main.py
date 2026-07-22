"""
Policy Engine — Devran Baştemur
================================
FastAPI tabanlı NAC (Network Access Control) karar motoru.

Kimlik doğrulama akışı:
  FreeRADIUS (rlm_rest) ──POST /authorize──► Policy Engine
  Policy Engine ──► PostgreSQL  (users / roles / permissions sorgusu + access_logs kaydı)
  Policy Engine ──► Redis       (rate-limit / brute-force koruması)
  Policy Engine ──► FreeRADIUS  (VLAN + erişim profili yanıtı)

Desteklenen roller (roles tablosundan dinamik okunur):
  admin    → VLAN 10, full_access
  employee → VLAN 20, limited_access
  guest    → VLAN 30, internet_only
  unknown  → REJECT
"""

from __future__ import annotations

from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import redis
import psycopg2
import os
import datetime
import json
import logging

# ---------------------------------------------------------------------------
# Loglama yapılandırması
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
)
logger = logging.getLogger("policy_engine")

# ---------------------------------------------------------------------------
# Wazuh agent'ın izlediği paylaşımlı log dosyası
# ---------------------------------------------------------------------------
LOG_FILE = "/var/log/shared/policy_engine.log"


def write_log(
    event_type: str,
    username: str,
    ip: str,
    decision: str,
    vlan: int | None = None,
    profile: str | None = None,
    detail: str = "",
) -> None:
    """Wazuh agent için yapılandırılmış JSON log satırı yazar."""
    entry = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "app": "policy_engine",
        "event": event_type,
        "username": username,
        "srcip": ip,
        "decision": decision,
        "vlan": vlan,
        "profile": profile,
        "detail": detail,
    }
    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as exc:
        logger.warning(f"Log dosyasına yazılamadı: {exc}")


# ---------------------------------------------------------------------------
# Ortam değişkenleri
# ---------------------------------------------------------------------------
REDIS_HOST     = os.getenv("REDIS_HOST",     "cache_redis")
REDIS_PORT     = int(os.getenv("REDIS_PORT", 6379))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "redis_secure_password")
RATE_LIMIT     = int(os.getenv("RATE_LIMIT", 5))    # maksimum başarısız deneme
RATE_WINDOW    = int(os.getenv("RATE_WINDOW", 60))  # saniye

DB_HOST = os.getenv("POSTGRES_HOST",     "db_postgres")
DB_PORT = int(os.getenv("POSTGRES_PORT", 5432))
DB_NAME = os.getenv("POSTGRES_DB",       "nac_db")
DB_USER = os.getenv("POSTGRES_USER",     "nac_admin")
DB_PASS = os.getenv("POSTGRES_PASSWORD", "nac_secure_password")

# ---------------------------------------------------------------------------
# Redis bağlantısı
# ---------------------------------------------------------------------------
redis_client = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    password=REDIS_PASSWORD,
    decode_responses=True,
    socket_connect_timeout=3,
)


# ===========================================================================
# VERİTABANI KATMANI
# ===========================================================================

def get_db() -> psycopg2.extensions.connection:
    """Yeni bir PostgreSQL bağlantısı döner."""
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASS,
        connect_timeout=5,
    )


def db_get_user(username: str) -> dict | None:
    """
    users tablosunda kullanıcıyı arar ve roles tablosuyla JOIN yaparak
    VLAN + profil bilgisini birlikte döner.

    Dönen dict örneği:
        {
          "username": "alice",
          "role": "employee",
          "active": True,
          "vlan_id": 20,
          "access_profile": "limited_access"
        }
    """
    sql = """
        SELECT u.username,
               u.role,
               u.active,
               r.vlan_id,
               r.access_profile
        FROM   users u
        JOIN   roles r ON r.role_name = u.role
        WHERE  u.username = %s
    """
    try:
        conn = get_db()
        cur  = conn.cursor()
        cur.execute(sql, (username,))
        row = cur.fetchone()
        cur.close()
        conn.close()
        if row:
            return {
                "username":       row[0],
                "role":           row[1],
                "active":         row[2],
                "vlan_id":        row[3],
                "access_profile": row[4],
            }
        return None
    except Exception as exc:
        logger.error(f"DB kullanıcı sorgu hatası: {exc}")
        return None


def db_get_permissions(role_name: str) -> list[dict]:
    """
    permissions tablosundan belirtilen role ait tüm erişim kurallarını döner.
    Kural motoru bu listeyi genişletilmiş kontrol için kullanabilir.
    """
    sql = """
        SELECT resource, port, protocol, allowed
        FROM   permissions
        WHERE  role_name = %s
        ORDER  BY id
    """
    try:
        conn = get_db()
        cur  = conn.cursor()
        cur.execute(sql, (role_name,))
        rows = cur.fetchall()
        cur.close()
        conn.close()
        return [
            {"resource": r[0], "port": r[1], "protocol": r[2], "allowed": r[3]}
            for r in rows
        ]
    except Exception as exc:
        logger.error(f"DB permissions sorgu hatası: {exc}")
        return []


def db_log_access(
    username: str,
    ip: str,
    decision: str,
    vlan: int | None,
    profile: str | None,
    detail: str = "",
) -> None:
    """Erişim kararını access_logs tablosuna yazar."""
    sql = """
        INSERT INTO access_logs (username, src_ip, decision, vlan, profile, detail, created_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """
    try:
        conn = get_db()
        cur  = conn.cursor()
        cur.execute(sql, (username, ip, decision, vlan, profile, detail,
                          datetime.datetime.utcnow()))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as exc:
        logger.error(f"DB log yazma hatası: {exc}")


# ===========================================================================
# KURAL MOTORU  (Dynamic Policy Rule Engine)
# ===========================================================================

def evaluate_policy(user: dict) -> dict:
    """
    Kullanıcı kaydındaki rol ve hesap durumuna göre erişim kararı üretir.
    Rol/VLAN/profil bilgisi doğrudan veritabanı sorgusundan (users JOIN roles)
    geldiği için sabit bir harita tutmaya gerek yoktur — tamamen dinamiktir.

    Kurallar (sırayla uygulanır):
      1. Hesap devre dışıysa (active=False)  → REJECT
      2. VLAN/profil veritabanında tanımlıysa  → ACCEPT + profil ata
      3. Hiçbir kural uymuyorsa               → REJECT

    Dönen dict:
        {
          "decision":      "ACCEPT" | "REJECT",
          "vlan":          int | None,
          "profile":       str | None,
          "reply_message": str,
        }
    """
    username = user["username"]
    role     = user["role"]
    active   = user["active"]
    vlan     = user.get("vlan_id")
    profile  = user.get("access_profile")

    # Kural 1: Devre dışı hesap
    if not active:
        return {
            "decision":      "REJECT",
            "vlan":          None,
            "profile":       None,
            "reply_message": f"Account '{username}' is disabled.",
        }

    # Kural 2: VLAN ve profil veritabanında tanımlı
    if vlan and profile:
        return {
            "decision":      "ACCEPT",
            "vlan":          vlan,
            "profile":       profile,
            "reply_message": f"{role.capitalize()} Access Granted – VLAN {vlan}",
        }

    # Kural 3: Tanımsız rol / eksik VLAN
    return {
        "decision":      "REJECT",
        "vlan":          None,
        "profile":       None,
        "reply_message": f"No policy defined for role '{role}'.",
    }


# ===========================================================================
# RATE-LIMIT KATMANI  (Redis tabanlı)
# ===========================================================================

def _fail_key(ip: str) -> str:
    return f"nac:fail:{ip}"


def is_rate_limited(ip: str) -> bool:
    """IP'nin blok eşiğini aşıp aşmadığını kontrol eder."""
    try:
        val = redis_client.get(_fail_key(ip))
        return val is not None and int(val) >= RATE_LIMIT
    except Exception as exc:
        logger.warning(f"Redis rate-limit kontrol hatası: {exc}")
        return False


def record_failed_attempt(ip: str) -> None:
    """Başarısız deneme sayacını artırır."""
    try:
        key = _fail_key(ip)
        redis_client.incr(key)
        redis_client.expire(key, RATE_WINDOW)
    except Exception as exc:
        logger.warning(f"Redis sayaç güncelleme hatası: {exc}")


def reset_failed_attempts(ip: str) -> None:
    """Başarılı girişte sayacı sıfırlar."""
    try:
        redis_client.delete(_fail_key(ip))
    except Exception as exc:
        logger.warning(f"Redis sayaç sıfırlama hatası: {exc}")


# ===========================================================================
# FASTAPI UYGULAMASI
# ===========================================================================

app = FastAPI(
    title="NAC Policy Engine",
    description=(
        "FreeRADIUS rlm_rest modülü için FastAPI tabanlı dinamik NAC karar motoru. "
        "Kullanıcı kimliğini PostgreSQL'de doğrular, rol/VLAN/profil atar ve "
        "tüm kararları access_logs tablosuna kaydeder."
    ),
    version="2.0.0",
)


# ---------------------------------------------------------------------------
# Middleware: /authorize için HTTP katmanı rate-limit
# ---------------------------------------------------------------------------
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    ip = request.client.host

    if request.url.path == "/authorize" and is_rate_limited(ip):
        logger.warning(f"[RATE-LIMIT BLOCKED] ip={ip}")
        write_log(
            event_type="RATE_LIMIT_BLOCKED",
            username="unknown",
            ip=ip,
            decision="REJECT",
            detail="Too many failed attempts – IP blocked by rate limiter",
        )
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"detail": "Too many requests. Temporarily blocked."},
        )

    return await call_next(request)


# ---------------------------------------------------------------------------
# İstek / Yanıt şemaları
# ---------------------------------------------------------------------------

class AuthorizeRequest(BaseModel):
    """FreeRADIUS rlm_rest modülünden gelen yetkilendirme isteği."""
    username:           str
    password:           str | None = None   # EAP-TLS akışında olmayabilir
    nas_ip:             str | None = None
    called_station_id:  str | None = None


class AuthorizeResponse(BaseModel):
    """FreeRADIUS'a döndürülen yetkilendirme yanıtı."""
    decision:       str             # "ACCEPT" veya "REJECT"
    vlan:           int | None = None
    profile:        str | None = None
    reply_message:  str = ""


# ===========================================================================
# ENDPOINT'LER
# ===========================================================================

# ---------------------------------------------------------------------------
# GET /  —  Sağlık kontrolü
# ---------------------------------------------------------------------------
@app.get("/", tags=["health"])
def health_check():
    """Servisin çalıştığını doğrular."""
    return {"status": "ok", "service": "policy_engine", "version": "2.0.0"}


# ---------------------------------------------------------------------------
# POST /authorize  —  Ana NAC karar noktası  ◄── FreeRADIUS buraya çağırır
# ---------------------------------------------------------------------------
@app.post("/authorize", response_model=AuthorizeResponse, tags=["policy"])
async def authorize(payload: AuthorizeRequest, request: Request):
    """
    FreeRADIUS'un rlm_rest modülü bu endpoint'i çağırır.

    İş akışı:
      1. Kaynak IP rate-limit kontrolü (middleware zaten 429 döndürdüyse buraya gelmez)
      2. PostgreSQL: users JOIN roles sorgusu → kullanıcı + VLAN + profil
      3. Kural motoru: evaluate_policy() → ACCEPT/REJECT kararı
      4. Redis: başarısız denemede sayaç++, başarılıda sıfırla
      5. Loglama: JSON dosyası (Wazuh) + access_logs tablosu (PostgreSQL)
      6. FreeRADIUS'a AuthorizeResponse döndür
    """
    ip       = request.client.host
    username = payload.username.strip()

    logger.info(f"[AUTHORIZE] username={username!r} src_ip={ip}")

    # ------------------------------------------------------------------
    # Adım 1 – Veritabanında kullanıcıyı ara (users JOIN roles)
    # ------------------------------------------------------------------
    user = db_get_user(username)

    if user is None:
        record_failed_attempt(ip)
        detail = f"User '{username}' not found in database."
        logger.warning(f"[REJECT] {detail}")
        write_log("AUTH_FAILURE", username, ip, "REJECT", detail=detail)
        db_log_access(username, ip, "REJECT", None, None, detail)
        return AuthorizeResponse(decision="REJECT", reply_message=detail)

    # ------------------------------------------------------------------
    # Adım 2 – Kural motoru kararı
    # ------------------------------------------------------------------
    result = evaluate_policy(user)

    # ------------------------------------------------------------------
    # Adım 3 – Rate-limit sayacını güncelle
    # ------------------------------------------------------------------
    if result["decision"] == "REJECT":
        record_failed_attempt(ip)
        logger.warning(
            f"[REJECT] username={username!r} "
            f"reason={result['reply_message']!r}"
        )
    else:
        reset_failed_attempts(ip)
        logger.info(
            f"[ACCEPT] username={username!r} "
            f"role={user['role']!r} "
            f"vlan={result['vlan']} "
            f"profile={result['profile']!r}"
        )

    # ------------------------------------------------------------------
    # Adım 4 – Loglama
    # ------------------------------------------------------------------
    event = "AUTH_SUCCESS" if result["decision"] == "ACCEPT" else "AUTH_FAILURE"
    write_log(
        event_type=event,
        username=username,
        ip=ip,
        decision=result["decision"],
        vlan=result.get("vlan"),
        profile=result.get("profile"),
        detail=result["reply_message"],
    )
    db_log_access(
        username=username,
        ip=ip,
        decision=result["decision"],
        vlan=result.get("vlan"),
        profile=result.get("profile"),
        detail=result["reply_message"],
    )

    # ------------------------------------------------------------------
    # Adım 5 – FreeRADIUS'a yanıt
    # ------------------------------------------------------------------
    return AuthorizeResponse(
        decision=result["decision"],
        vlan=result.get("vlan"),
        profile=result.get("profile"),
        reply_message=result["reply_message"],
    )


# ---------------------------------------------------------------------------
# GET /users/{username}  —  Kullanıcı + rol + izin bilgisi
# ---------------------------------------------------------------------------
@app.get("/users/{username}", tags=["debug"])
def get_user(username: str):
    """
    Kullanıcı kaydını roles JOIN ile birlikte döndürür.
    İzin listesi (permissions tablosu) de yanıta eklenir.
    """
    user = db_get_user(username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{username}' not found.",
        )
    permissions = db_get_permissions(user["role"])
    return {**user, "permissions": permissions}


# ---------------------------------------------------------------------------
# GET /roles  —  Tüm rol tanımlarını listele
# ---------------------------------------------------------------------------
@app.get("/roles", tags=["debug"])
def list_roles():
    """roles tablosundaki tüm rol tanımlarını döndürür."""
    try:
        conn = get_db()
        cur  = conn.cursor()
        cur.execute(
            "SELECT role_name, vlan_id, access_profile, description FROM roles ORDER BY vlan_id"
        )
        rows = cur.fetchall()
        cur.close()
        conn.close()
        return [
            {
                "role_name":      r[0],
                "vlan_id":        r[1],
                "access_profile": r[2],
                "description":    r[3],
            }
            for r in rows
        ]
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# GET /logs  —  Son erişim loglarını getir
# ---------------------------------------------------------------------------
@app.get("/logs", tags=["debug"])
def get_logs(limit: int = 50):
    """access_logs tablosundaki son kararları döndürür."""
    try:
        conn = get_db()
        cur  = conn.cursor()
        cur.execute(
            """
            SELECT id, username, src_ip, decision, vlan, profile, detail, created_at
            FROM   access_logs
            ORDER  BY created_at DESC
            LIMIT  %s
            """,
            (limit,),
        )
        rows = cur.fetchall()
        cur.close()
        conn.close()
        return [
            {
                "id":         r[0],
                "username":   r[1],
                "src_ip":     r[2],
                "decision":   r[3],
                "vlan":       r[4],
                "profile":    r[5],
                "detail":     r[6],
                "created_at": r[7].isoformat() if r[7] else None,
            }
            for r in rows
        ]
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# POST /login  —  Geriye dönük uyumluluk
# ---------------------------------------------------------------------------
@app.post("/login", tags=["legacy"])
def login():
    """Orijinal rate-limit test endpoint'i (eski testler için korundu)."""
    return {"message": "Login Endpoint - Protected by Rate Limiting"}
