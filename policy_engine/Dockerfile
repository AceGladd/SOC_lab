FROM python:3.10-slim

WORKDIR /app

# Bağımlılıkları kur
RUN pip install --no-cache-dir \
    fastapi==0.111.0 \
    uvicorn==0.29.0 \
    psycopg2-binary==2.9.9 \
    redis==5.0.4 \
    pydantic==2.7.1

# Uygulama kodunu kopyala
COPY . .

# Port (yalnızca iç ağa açık, host'a expose edilmiyor)
EXPOSE 8000

# FastAPI başlatma
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "info"]
