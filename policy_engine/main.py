from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import redis
import os
import datetime

import json

def write_log(ip):
    # Log dosyasının yolunu ve adını belirleme
    log_data = {
        "timestamp": datetime.datetime.now().isoformat(),
        "app": "policy_engine",
        "message": f"SECURITY ALERT: Brute-Force from {ip}!",
        "srcip": ip
    }
    with open("/var/log/shared/policy_engine.log", "a") as f:
        f.write(json.dumps(log_data) + "\n")
        
app = FastAPI()
r = redis.Redis(host='cache_redis', port=6379, password=os.getenv('REDIS_PASSWORD', 'redis_secure_password'), decode_responses=True)

@app.middleware("http")
async def limit_requests(request: Request, call_next):
    ip = request.client.host
    
    # Sadece login sayfasına saniyede 5 istek limiti
    if request.url.path == "/login":
        if r.get(ip) and int(r.get(ip)) >= 5:
            print(f"SECURITY ALERT: Brute-Force from {ip}!")
            write_log(ip)
            return JSONResponse(status_code=429, content={"detail": "Blocked."})
        
        # ip adresini kaydet ve sayacı artır
        r.incr(ip)
        r.expire(ip, 60)
        
    return await call_next(request)

@app.get("/")
def home():
    return {"msg": "Policy Engine OK"}

@app.post("/login")
def login():
    return {"message": "Login Endpoint - Protected by Rate Limiting"}
