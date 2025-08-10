from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from datetime import datetime
from datetime import date
from zoneinfo import ZoneInfo
import time
import mysql.connector
from mysql.connector import Error
import os
import hmac
import hashlib

# Load configuration from environment variables
API_KEY = os.getenv("API_KEY")

# New: load org secret and allowed hashes
ORG_SECRET = os.getenv("ORG_SECRET", "").strip()  # same value stored on clients
ALLOWED_HASHES = os.getenv("ALLOWED_HASHES", "").split(",")  # comma-separated list

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", "3306")),
    "user": os.getenv("DB_USER", "passworduser"),
    "password": os.getenv("DB_PASSWORD", "passwordpass"),
    "database": os.getenv("DB_NAME", "passwordstore")
}

# Initialize FastAPI
app = FastAPI()

@app.middleware("http")
async def get_real_ip(request: Request, call_next):
    headers = request.headers
    forwarded_for = headers.get("x-forwarded-for")
    real_ip = headers.get("x-real-ip")

    if forwarded_for:
        ip = forwarded_for.split(",")[0].strip()
    elif real_ip:
        ip = real_ip
    else:
        ip = request.client.host

    print(f"Request from Client IP: {ip}")
    response = await call_next(request)
    return response

# Existing model
class SecretIn(BaseModel):
    username: str
    password: str
    fingerprint: str  # new
    ts: int           # new
    hmac: str         # new

# Reusable DB connection function
def get_db_connection(retries=10, delay=3):
    for attempt in range(retries):
        try:
            conn = mysql.connector.connect(**DB_CONFIG)
            if conn.is_connected():
                return conn
        except Error as e:
            print(f"DB connection attempt {attempt + 1} failed: {e}")
            time.sleep(delay)
    raise Exception(f"Failed to connect to database after {retries} attempts")

def ensure_table_exists():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_entries (
            id INT AUTO_INCREMENT PRIMARY KEY,
            timestamp DATETIME,
            username VARCHAR(255),
            password TEXT
        )
    """)
    conn.commit()
    cursor.close()
    conn.close()

def cleanup_old_entries():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT username FROM password_entries")
    usernames = cursor.fetchall()

    for (username,) in usernames:
        cursor.execute("""
            DELETE FROM password_entries
            WHERE username = %s
              AND id NOT IN (
                  SELECT id FROM (
                      SELECT id
                      FROM password_entries
                      WHERE username = %s
                      ORDER BY timestamp DESC
                      LIMIT 5
                  ) as recent
              )
        """, (username, username))

    conn.commit()
    cursor.close()
    conn.close()

ensure_table_exists()
cleanup_old_entries()

# Helper: verify device authentication
def verify_device(fingerprint: str, ts: int, provided_hmac: str):
    # check if fingerprint is in allowlist
    if fingerprint not in ALLOWED_HASHES:
        raise HTTPException(status_code=403, detail="Device not authorized")

    # timestamp freshness check (5 min window)
    now = int(time.time())
    if abs(now - ts) > 300:
        raise HTTPException(status_code=401, detail="Request expired")

    message = f"{fingerprint}|{ts}"
    computed_hmac = hmac.new(
        ORG_SECRET.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    # validate HMAC
    if not hmac.compare_digest(computed_hmac, provided_hmac):
        raise HTTPException(status_code=401, detail="Invalid device signature")

# POST /store
@app.post("/store")
async def store_secret(request: Request, secret: SecretIn):
    if request.headers.get("x-api-key") != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # new: verify device auth
    verify_device(secret.fingerprint, secret.ts, secret.hmac)

    now_est = datetime.now(ZoneInfo("America/New_York"))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO password_entries (timestamp, username, password) VALUES (%s, %s, %s)",
        (now_est.strftime('%Y-%m-%d %H:%M:%S'), secret.username, secret.password)
    )
    conn.commit()
    cursor.close()
    conn.close()

    return {"status": "stored"}

class UsernameQuery(BaseModel):
    username: str
    fingerprint: str  # new
    ts: int           # new
    hmac: str         # new

@app.post("/latest")
async def get_latest_for_username(request: Request, query: UsernameQuery):
    if request.headers.get("x-api-key") != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # new: verify device auth
    verify_device(query.fingerprint, query.ts, query.hmac)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT timestamp, username, password
        FROM password_entries
        WHERE username = %s
        ORDER BY timestamp DESC
        LIMIT 1
    """, (query.username,))

    result = cursor.fetchone()
    cursor.close()
    conn.close()

    if not result:
        raise HTTPException(status_code=404, detail=f"No entries found for username '{query.username}'")

    return {
        "timestamp": result[0].isoformat(),
        "username": result[1],
        "password": result[2]
    }

@app.post("/all")
async def get_all_for_username(request: Request, query: UsernameQuery):
    if request.headers.get("x-api-key") != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # new: verify device auth
    verify_device(query.fingerprint, query.ts, query.hmac)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT timestamp, username, password
        FROM password_entries
        WHERE username = %s
        ORDER BY timestamp DESC
    """, (query.username,))

    results = cursor.fetchall()
    cursor.close()
    conn.close()

    if not results:
        raise HTTPException(status_code=404, detail=f"No entries found for username '{query.username}'")

    return [
        {
            "timestamp": row[0].isoformat(),
            "username": row[1],
            "password": row[2]
        }
        for row in results
    ]
