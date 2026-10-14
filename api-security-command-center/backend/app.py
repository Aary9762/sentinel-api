import os
import re
import json
import time
from datetime import datetime, timezone
from typing import Dict, List, Set
from collections import defaultdict

from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

# Database and Risk Engine Imports
from database.db_client import (
    init_db,
    reset_db,
    save_traffic_log,
    upsert_api_inventory,
    create_alert,
    get_inventory,
    get_alerts,
    get_traffic_logs
)
from database.models import APIEndpointDB, SecurityAlertDB, TrafficLogDB
from engine.risk_scorer import evaluate_endpoint_from_state, calculate_endpoint_risk, EndpointContext

# Initialize database
init_db()

app = FastAPI(
    title="API Security & Governance Command Center",
    description="Passive traffic discovery, shadow API detection, and runtime abuse telemetry",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from fastapi.staticfiles import StaticFiles

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(os.path.dirname(BASE_DIR), "frontend")
ASSETS_DIR = os.path.join(FRONTEND_DIR, "assets")
OPENAPI_PATH = os.path.join(BASE_DIR, "openapi.json")

if os.path.exists(ASSETS_DIR):
    app.mount("/assets", StaticFiles(directory=ASSETS_DIR), name="assets")

# Load OpenAPI specification
documented_routes: Set[str] = set()

def load_openapi_spec():
    global documented_routes
    documented_routes.clear()
    if os.path.exists(OPENAPI_PATH):
        try:
            with open(OPENAPI_PATH, "r", encoding="utf-8") as f:
                spec = json.load(f)
                paths = spec.get("paths", {})
                for path, methods in paths.items():
                    for method in methods.keys():
                        documented_routes.add(f"{method.upper()}:{path.rstrip('/')}")
        except Exception as e:
            print(f"[Warning] Failed to parse openapi.json: {e}")

load_openapi_spec()

# Runtime abuse tracking state (in-memory sliding window & token tracking)
# IP -> list of request timestamps (epoch floats)
ip_request_timestamps: Dict[str, List[float]] = defaultdict(list)
# Token -> set of distinct caller IPs seen
token_ips: Dict[str, Set[str]] = defaultdict(set)
# Dedup alerts within short window to avoid alert spamming
alert_dedup_cache: Dict[str, float] = {}

SCRAPING_THRESHOLD = 15
SCRAPING_WINDOW_SECONDS = 10.0
TOKEN_REPLAY_IP_THRESHOLD = 2

# PII Pattern definitions
PII_KEYWORDS = ["user", "email", "ssn", "password", "secret", "credit_card", "card", "phone", "account", "balance", "token", "salary", "identity", "export"]
PII_REGEX = re.compile(r"(\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b|\b\d{3}-\d{2}-\d{4}\b|\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b)")


def normalize_route(raw_path: str) -> str:
    """
    Normalizes dynamic routes:
    /api/v1/users/123 -> /api/v1/users/{id}
    /api/v1/users/user_999/balance -> /api/v1/users/{id}/balance
    """
    clean_path = raw_path.split("?")[0].rstrip("/")
    if not clean_path:
        return "/"

    # Normalize user ID segments (numeric or user_ prefix or UUID or id-like)
    normalized = re.sub(r"/users/(user_[a-zA-Z0-9]+|\d+|[0-9a-fA-F-]{8,})(/|$)", r"/users/{id}\2", clean_path)
    normalized = re.sub(r"/accounts/([a-zA-Z0-9_-]+)(/|$)", r"/accounts/{id}\2", normalized)
    return normalized


def extract_resource_id(raw_path: str) -> str:
    """Extracts target resource identifier from dynamic route if present."""
    match = re.search(r"/users/([^/]+)", raw_path)
    if match:
        return match.group(1)
    return None


def detect_pii(path: str, body_str: str) -> bool:
    """Detects presence of PII in path or body payload."""
    path_lower = path.lower()
    for kw in PII_KEYWORDS:
        if kw in path_lower:
            return True

    if body_str:
        body_lower = body_str.lower()
        for kw in PII_KEYWORDS:
            if kw in body_lower:
                return True
        if PII_REGEX.search(body_str):
            return True
    return False


# =====================================================================
# Traffic Interceptor & Discovery Middleware
# =====================================================================
@app.middleware("http")
async def traffic_interception_middleware(request: Request, call_next):
    raw_path = request.url.path
    method = request.method.upper()

    # Skip static frontend dashboard routes and internal governance APIs
    if (
        raw_path.startswith("/api/governance")
        or raw_path.startswith("/static")
        or raw_path in ("/", "/index.html", "/favicon.ico")
    ):
        return await call_next(request)

    caller_ip = request.headers.get("x-forwarded-for") or (request.client.host if request.client else "127.0.0.1")
    if "," in caller_ip:
        caller_ip = caller_ip.split(",")[0].strip()

    # Authentication inspection
    auth_header = request.headers.get("authorization", "")
    auth_type = "None"
    token = None
    if auth_header.startswith("Bearer "):
        auth_type = "Bearer Token"
        token = auth_header[7:].strip()
    elif auth_header.startswith("Basic "):
        auth_type = "Basic"
        token = auth_header[6:].strip()
    elif "x-api-key" in request.headers:
        auth_type = "API Key"
        token = request.headers.get("x-api-key")

    # Session user extraction
    session_user_id = request.headers.get("x-user-id")
    if not session_user_id and token and token.startswith("user_"):
        session_user_id = token.split("_")[0] + "_" + token.split("_")[1]

    # Read body for inspection
    body_bytes = await request.body()
    body_str = body_bytes.decode("utf-8", errors="ignore") if body_bytes else ""

    # Reconstruct request stream for route handlers
    async def receive():
        return {"type": "http.request", "body": body_bytes}

    request._receive = receive

    # 1. Normalize Dynamic Route
    normalized_path = normalize_route(raw_path)
    target_resource_id = extract_resource_id(raw_path)

    # 2. Shadow API Detection
    route_key = f"{method}:{normalized_path.rstrip('/')}"
    is_shadow = route_key not in documented_routes

    # 3. PII Detection
    contains_pii = detect_pii(raw_path, body_str)

    current_time = time.time()
    now_iso = datetime.now(timezone.utc).isoformat()

    # 4. Save Traffic Log
    save_traffic_log({
        "timestamp": now_iso,
        "method": method,
        "endpoint": normalized_path,
        "caller_ip": caller_ip,
        "token_user_id": session_user_id,
        "target_resource_id": target_resource_id,
        "payload_size_bytes": len(body_bytes),
        "token": (token[:12] + "...") if token and len(token) > 12 else token,
        "auth_type": auth_type,
        "status_code": 200
    })

    # =================================================================
    # Runtime Abuse Heuristics
    # =================================================================

    # A. BOLA (Broken Object Level Authorization)
    if session_user_id and target_resource_id:
        # Compare session owner with targeted resource
        if session_user_id != target_resource_id and target_resource_id not in ("me", "{id}"):
            dedup_key = f"BOLA:{caller_ip}:{normalized_path}:{session_user_id}:{target_resource_id}"
            if current_time - alert_dedup_cache.get(dedup_key, 0) > 3.0:
                alert_dedup_cache[dedup_key] = current_time
                create_alert(
                    timestamp=now_iso,
                    endpoint=normalized_path,
                    alert_type="BOLA",
                    severity="CRITICAL",
                    caller_ip=caller_ip,
                    details=f"BOLA Breach: Authenticated session '{session_user_id}' requested private resource belonging to '{target_resource_id}'"
                )

    # B. Token Replay (Concurrent usage across > 2 distinct IPs)
    if token:
        token_ips[token].add(caller_ip)
        if len(token_ips[token]) > TOKEN_REPLAY_IP_THRESHOLD:
            distinct_ips = list(token_ips[token])
            dedup_key = f"REPLAY:{token}:{len(distinct_ips)}"
            if current_time - alert_dedup_cache.get(dedup_key, 0) > 4.0:
                alert_dedup_cache[dedup_key] = current_time
                create_alert(
                    timestamp=now_iso,
                    endpoint=normalized_path,
                    alert_type="TOKEN_REPLAY",
                    severity="HIGH",
                    caller_ip=caller_ip,
                    details=f"Token Replay: Credential '{token[:10]}...' concurrently active across {len(distinct_ips)} distinct IPs: {', '.join(distinct_ips)}"
                )

    # C. Scraping Anomaly (> 15 requests in 10s rolling window)
    timestamps = ip_request_timestamps[caller_ip]
    timestamps.append(current_time)
    # Evict timestamps older than 10s window
    ip_request_timestamps[caller_ip] = [t for t in timestamps if current_time - t <= SCRAPING_WINDOW_SECONDS]
    count_in_window = len(ip_request_timestamps[caller_ip])

    if count_in_window > SCRAPING_THRESHOLD:
        dedup_key = f"SCRAPING:{caller_ip}"
        if current_time - alert_dedup_cache.get(dedup_key, 0) > 5.0:
            alert_dedup_cache[dedup_key] = current_time
            create_alert(
                timestamp=now_iso,
                endpoint=normalized_path,
                alert_type="SCRAPING",
                severity="HIGH",
                caller_ip=caller_ip,
                details=f"Scraping Anomaly: IP '{caller_ip}' breached rate limit with {count_in_window} requests in 10s window (threshold: {SCRAPING_THRESHOLD})"
            )

    # 5. Dynamic Risk Scoring Calculation
    raw_alerts = get_alerts(limit=50)
    alerts_dict_list = [
        {"endpoint": a.endpoint, "alert_type": a.alert_type, "severity": a.severity}
        for a in raw_alerts
    ]
    
    # Check if endpoint was previously observed to have auth or PII
    existing_items = get_inventory()
    effective_auth = auth_type
    effective_pii = contains_pii
    for it in existing_items:
        if it.method == method and it.endpoint == normalized_path:
            if effective_auth == "None" and it.auth_type and it.auth_type != "None":
                effective_auth = it.auth_type
            if it.contains_pii:
                effective_pii = True
            break

    score, severity, reasons = evaluate_endpoint_from_state(
        method=method,
        endpoint=normalized_path,
        auth_type=effective_auth,
        is_shadow=is_shadow,
        contains_pii=effective_pii,
        alerts=alerts_dict_list
    )

    # Upsert Discovered Endpoint into Inventory
    upsert_api_inventory(
        method=method,
        endpoint=normalized_path,
        is_shadow=is_shadow,
        risk_score=score,
        reasons=reasons,
        auth_type=effective_auth,
        contains_pii=effective_pii,
        severity=severity,
        increment_call=True
    )

    response = await call_next(request)
    return response


# =====================================================================
# Governance & Dashboard Telemetry Endpoints
# =====================================================================

@app.get("/api/governance/kpis")
def get_kpis():
    inventory = get_inventory()
    alerts = get_alerts(limit=500)
    traffic = get_traffic_logs(limit=500)

    total_apis = len(inventory)
    shadow_apis = sum(1 for e in inventory if e.is_shadow)
    managed_apis = total_apis - shadow_apis
    active_alerts = len(alerts)
    critical_alerts = sum(1 for a in alerts if a.severity in ("CRITICAL", "HIGH"))
    pii_endpoints = sum(1 for e in inventory if e.contains_pii)
    avg_risk = round(sum(e.risk_score for e in inventory) / total_apis, 1) if total_apis > 0 else 0

    return {
        "total_apis": total_apis,
        "shadow_apis": shadow_apis,
        "managed_apis": managed_apis,
        "active_alerts": active_alerts,
        "critical_alerts": critical_alerts,
        "pii_endpoints": pii_endpoints,
        "avg_risk_score": avg_risk,
        "total_requests_observed": len(traffic)
    }


@app.get("/api/governance/inventory")
def get_api_inventory():
    items = get_inventory()
    result = []
    for item in items:
        try:
            reasons = json.loads(item.risk_reasons) if item.risk_reasons else []
        except Exception:
            reasons = [item.risk_reasons] if item.risk_reasons else []

        result.append({
            "id": item.id,
            "method": item.method,
            "endpoint": item.endpoint,
            "is_shadow": item.is_shadow,
            "risk_score": item.risk_score,
            "severity": item.severity,
            "risk_reasons": reasons,
            "alert_count": item.alert_count,
            "auth_type": item.auth_type,
            "contains_pii": item.contains_pii,
            "total_calls": item.total_calls,
            "last_seen": item.last_seen
        })
    return result


@app.get("/api/governance/alerts")
def get_security_alerts():
    alerts = get_alerts(limit=100)
    return [
        {
            "id": a.id,
            "timestamp": a.timestamp,
            "endpoint": a.endpoint,
            "abuse_type": a.alert_type,
            "severity": a.severity,
            "caller_ip": a.caller_ip or "Unknown IP",
            "details": a.details
        }
        for a in alerts
    ]


@app.get("/api/governance/traffic")
def get_traffic_stream():
    logs = get_traffic_logs(limit=50)
    return [
        {
            "id": l.id,
            "timestamp": l.timestamp,
            "method": l.method,
            "endpoint": l.endpoint,
            "caller_ip": l.caller_ip,
            "user_id": l.token_user_id,
            "target_resource_id": l.target_resource_id,
            "token": l.token,
            "auth_type": l.auth_type,
            "payload_size_bytes": l.payload_size_bytes,
            "status_code": l.status_code
        }
        for l in logs
    ]


@app.get("/api/governance/topology")
def get_topology():
    """Generates 3D node and link topology data for Three.js spatial graph."""
    inventory = get_inventory()
    alerts = get_alerts(limit=50)

    nodes = [
        {
            "id": "gateway_root",
            "label": "API Gateway Core",
            "type": "gateway",
            "risk": 0,
            "is_shadow": False,
            "calls": 100
        }
    ]
    links = []

    for item in inventory:
        node_id = f"{item.method}:{item.endpoint}"
        nodes.append({
            "id": node_id,
            "label": f"{item.method} {item.endpoint}",
            "type": "shadow" if item.is_shadow else "managed",
            "risk": item.risk_score,
            "severity": item.severity,
            "is_shadow": item.is_shadow,
            "contains_pii": item.contains_pii,
            "alerts": item.alert_count,
            "calls": item.total_calls
        })
        links.append({
            "source": "gateway_root",
            "target": node_id,
            "active": item.alert_count > 0
        })

    return {"nodes": nodes, "links": links, "alert_count": len(alerts)}


@app.get("/api/governance/download")
@app.get("/download")
def download_project_zip():
    """Provides direct browser download of the complete project zip archive."""
    zip_path = os.path.join(os.path.dirname(BASE_DIR), "api-security-command-center.zip")
    if not os.path.exists(zip_path):
        # Fallback to scratch root
        zip_path = r"C:\Users\arvin\.gemini\antigravity\scratch\api-security-command-center.zip"
    if os.path.exists(zip_path):
        return FileResponse(
            path=zip_path,
            filename="api-security-command-center.zip",
            media_type="application/zip"
        )
    raise HTTPException(status_code=404, detail="Zip archive not found")


@app.post("/api/governance/reset")
def reset_system_state():
    """Resets database and in-memory caches to a pristine state."""
    reset_db()
    ip_request_timestamps.clear()
    token_ips.clear()
    alert_dedup_cache.clear()
    return {"status": "success", "message": "All state reset successfully"}


@app.post("/api/governance/simulate")
def trigger_simulation():
    """Triggers the full test simulation script synchronously or returns execution results."""
    import subprocess
    import sys
    sim_script = os.path.join(os.path.dirname(BASE_DIR), "simulate.py")
    if os.path.exists(sim_script):
        res = subprocess.run([sys.executable, sim_script], capture_output=True, text=True, timeout=30)
        return {"status": "completed", "output": res.stdout, "errors": res.stderr}
    return {"status": "error", "message": "simulate.py not found"}


# =====================================================================
# Mock Vulnerable Target API (Documented & Shadow)
# =====================================================================

# Documented Endpoint 1: User Profile
@app.get("/api/v1/users/{id}")
def get_user_profile(id: str, request: Request):
    return {
        "status": "success",
        "user_id": id,
        "name": f"Enterprise User {id}",
        "email": f"client_{id}@enterprise.com",
        "role": "customer",
        "tier": "platinum",
        "kyc_verified": True
    }


# Documented Endpoint 2: Account Balance
@app.get("/api/v1/users/{id}/balance")
def get_user_balance(id: str, request: Request):
    return {
        "status": "success",
        "account_id": f"ACC-{id}-098",
        "owner_id": id,
        "balance": 14250.75,
        "currency": "USD",
        "available_credit": 50000.00
    }


# Documented Endpoint 3: Payments
@app.post("/api/v1/payments")
async def create_payment(request: Request):
    body = await request.json()
    return {
        "status": "executed",
        "transaction_id": "TXN-9988231",
        "amount": body.get("amount", 250.0),
        "currency": body.get("currency", "USD"),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


# Shadow / Hidden Endpoint 1: System Debug Dump (undocumented)
@app.get("/api/v2/debug")
def system_debug_dump():
    return {
        "status": "DEBUG_ACTIVE",
        "server_kernel": "Linux 6.8.0-generic",
        "internal_ip": "10.142.0.8",
        "env_dump": {
            "SECRET_KEY": "jwt_super_secret_dev_key_x99",
            "DB_CONN": "sqlite:///database/api_security.db",
            "DEBUG_MODE": True
        },
        "thread_workers": 8
    }


# Shadow / Hidden Endpoint 2: Legacy Admin Export (undocumented)
@app.get("/api/v1/admin/export")
def legacy_admin_export():
    return {
        "status": "LEGACY_EXPORT",
        "format": "csv",
        "records_exported": 5000,
        "notice": "Unmaintained admin route from 2023 deprecation cycle",
        "data_dump_preview": [
            {"user_id": "usr_001", "email": "sarah.connor@cyberdyne.net", "ssn": "987-65-4321"},
            {"user_id": "usr_002", "email": "john.wick@continental.org", "ssn": "123-45-6789"}
        ]
    }


# =====================================================================
# Serve Frontend Static Dashboard
# =====================================================================

@app.get("/", response_class=HTMLResponse)
def serve_index():
    index_file = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_file):
        with open(index_file, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h1>API Security Command Center Frontend Index Not Found</h1>")
