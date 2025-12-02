# app.py
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from urllib.parse import urlparse
import re
import math
import tldextract
import sqlite3
import time
import datetime
from typing import Tuple, List, Dict, Any

# --------------------------
# Configuration
# --------------------------
BRAND_TOKENS = ["paypal", "google", "amazon", "facebook", "netflix", "bank", "apple", "microsoft", "github"]
DB_FILE = "checks.db"

# --------------------------
# App + CORS
# --------------------------
app = FastAPI(title="PhishCheck API")

# Development CORS - ok for local testing. For production, restrict origins.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --------------------------
# Request model
# --------------------------
class URLQuery(BaseModel):
    url: str

# --------------------------
# Utilities / Feature extraction
# --------------------------
def is_ip_hostname(hostname: str) -> bool:
    # IPv4 dotted decimal check (simple)
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname))

def hostname_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c)/len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)

def extract_features(url: str) -> Dict[str, Any]:
    # Ensure scheme for parsing
    u = url if re.match(r"^\w+://", url) else "http://" + url
    parsed = urlparse(u)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    ext = tldextract.extract(hostname)
    registered_domain = (ext.domain + (("." + ext.suffix) if ext.suffix else "")).lower()

    tokens_present = [b for b in BRAND_TOKENS if b in hostname]

    features = {
        "url": url,
        "scheme": parsed.scheme,
        "hostname": hostname,
        "registered_domain": registered_domain,
        "path": path,
        "query": query,
        "url_length": len(url),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "has_ip": int(is_ip_hostname(hostname)),
        "count_dots": hostname.count("."),
        "count_hyphen": hostname.count("-"),
        "count_at": url.count("@"),
        "count_double_slash": url.count("//") - (1 if url.startswith("http") else 0),
        "hostname_entropy": round(hostname_entropy(hostname), 4),
        "has_punycode": int("xn--" in hostname),
        "has_https": int(parsed.scheme == "https"),
        "brand_tokens": tokens_present,
        "brand_in_registered_domain": any(b in registered_domain for b in BRAND_TOKENS),
    }
    return features

# --------------------------
# Heuristic scoring & decision
# --------------------------
def heuristic_score(features: Dict[str, Any]) -> Tuple[float, List[str], bool]:
    """
    Returns: (score [0..1], reasons[], must_flag)
    must_flag = True means absolute red-flag (e.g. '@', IP, punycode)
    """
    score = 0.0
    reasons: List[str] = []
    must_flag = False

    # Absolute red flags (immediate concern)
    if features["count_at"] > 0:
        reasons.append("Contains @ (classic obfuscation)")
        must_flag = True
    if features["has_ip"]:
        reasons.append("Raw IP used as hostname")
        must_flag = True
    if features["has_punycode"]:
        reasons.append("Punycode (xn--) detected — possible homograph")
        must_flag = True

    # Weighted signals (tweakable)
    if features["url_length"] > 75:
        score += 0.20
        reasons.append(f"Long URL ({features['url_length']} chars)")
    if features["count_hyphen"] > 2:
        score += 0.08
        reasons.append("Multiple hyphens in hostname")
    if features["count_dots"] > 4:
        score += 0.10
        reasons.append("Many subdomains")
    if not features["has_https"]:
        score += 0.05
        reasons.append("No HTTPS")
    if features["hostname_entropy"] > 3.8:
        score += 0.10
        reasons.append("High entropy in hostname (random-looking)")
    if features["count_double_slash"] > 1:
        score += 0.06
        reasons.append("Strange double-slash pattern in URL")

    # Brand token logic
    if features["brand_tokens"]:
        score += 0.06 * len(features["brand_tokens"])
        reasons.append("Brand-like token(s) in hostname: " + ", ".join(features["brand_tokens"]))
        if not features["brand_in_registered_domain"]:
            score += 0.25
            reasons.append("Brand token not present in registered domain (possible impersonation)")

    # clamp
    score = min(score, 1.0)
    return round(score, 3), reasons, must_flag

def decision_from_features(features: Dict[str, Any]) -> Tuple[str, float, List[str]]:
    score, reasons, must_flag = heuristic_score(features)
    if must_flag:
        verdict = "phishy"
        final_score = max(0.9, score)
    else:
        if score >= 0.8:
            verdict = "phishy"
        elif score >= 0.35:
            verdict = "suspicious"
        else:
            verdict = "likely safe"
        final_score = score
    return verdict, round(final_score, 3), reasons

# --------------------------
# Simple logging to SQLite
# --------------------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS checks (
            ts REAL,
            iso TEXT,
            url TEXT,
            verdict TEXT,
            score REAL,
            reasons TEXT,
            hostname TEXT,
            registered_domain TEXT
        )
        """
    )
    conn.commit()
    conn.close()

def log_check(url: str, verdict: str, score: float, reasons: List[str], features: Dict[str, Any]):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        ts = time.time()
        iso = datetime.datetime.utcnow().isoformat()
        c.execute(
            "INSERT INTO checks VALUES (?,?,?,?,?,?,?,?)",
            (ts, iso, url, verdict, score, ";".join(reasons), features.get("hostname",""), features.get("registered_domain",""))
        )
        conn.commit()
    except Exception as e:
        # logging should not break the API
        print("DB log error:", e)
    finally:
        try: conn.close()
        except: pass

# Initialize DB at startup
init_db()

# --------------------------
# Endpoints
# --------------------------
@app.get("/health")
def health():
    return {"status": "ok", "time": datetime.datetime.utcnow().isoformat()}

@app.post("/api/check")
def check_url(data: URLQuery):
    url = (data.url or "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="Empty URL")

    # Extract features and decide
    features = extract_features(url)
    verdict, final_score, reasons = decision_from_features(features)

    # Log the check (best-effort)
    log_check(url, verdict, final_score, reasons, features)

    # Response shape
    resp = {
        "url": url,
        "verdict": verdict,
        "final_score": final_score,
        "heuristic_reasons": reasons,
        "features": {
            "hostname": features.get("hostname"),
            "registered_domain": features.get("registered_domain"),
            "url_length": features.get("url_length"),
            "has_ip": features.get("has_ip"),
            "has_punycode": features.get("has_punycode"),
            "hostname_entropy": features.get("hostname_entropy"),
            "brand_tokens": features.get("brand_tokens"),
        },
    }
    return resp

# --------------------------
# If you want to run this file directly:
# uvicorn app:app --reload
# --------------------------
