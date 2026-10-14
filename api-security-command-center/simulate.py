#!/usr/bin/env python3
"""
API Security & Governance Command Center - Traffic Simulation Script
Demonstrates passive endpoint discovery, shadow API identification,
and runtime abuse heuristics (BOLA, Token Replay, Scraping Anomaly).
"""

import sys
import time
import requests

if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

BASE_URL = "http://127.0.0.1:8000"

def log_step(title):
    print(f"\n=======================================================")
    print(f"[*] {title}")
    print(f"=======================================================")

def check_server_online():
    try:
        r = requests.get(f"{BASE_URL}/api/governance/kpis", timeout=3)
        return r.status_code == 200
    except Exception:
        return False

def run_simulation():
    print("🚀 Starting Security Simulation against", BASE_URL)

    if not check_server_online():
        print("❌ Error: Command Center backend is not running at", BASE_URL)
        print("Please start it first using: python backend/app.py or uvicorn backend.app:app --port 8000")
        sys.exit(1)

    # 0. Optional: Reset to fresh state before simulation
    try:
        requests.post(f"{BASE_URL}/api/governance/reset", timeout=5)
        print("✔ Database and rate-tracking cache reset to clean baseline.")
    except Exception as e:
        print("Notice: Proceeding with existing state:", e)

    # 1. Normal Authorized Traffic to Documented Endpoints
    log_step("Phase 1: Sending Normal Authorized Traffic (Documented Endpoints)")
    
    # User 101 requests their own profile
    res1 = requests.get(
        f"{BASE_URL}/api/v1/users/user_101",
        headers={
            "Authorization": "Bearer token_usr_101_legit",
            "X-User-Id": "user_101",
            "X-Forwarded-For": "192.168.1.100"
        }
    )
    print(f"  [GET /api/v1/users/user_101] Status: {res1.status_code} - Discovered /api/v1/users/{{id}}")

    # User 101 checks their own balance
    res2 = requests.get(
        f"{BASE_URL}/api/v1/users/user_101/balance",
        headers={
            "Authorization": "Bearer token_usr_101_legit",
            "X-User-Id": "user_101",
            "X-Forwarded-For": "192.168.1.100"
        }
    )
    print(f"  [GET /api/v1/users/user_101/balance] Status: {res2.status_code} - Discovered /api/v1/users/{{id}}/balance")

    # Payment execution
    res3 = requests.post(
        f"{BASE_URL}/api/v1/payments",
        headers={
            "Authorization": "Bearer token_usr_101_legit",
            "X-Forwarded-For": "192.168.1.100",
            "Content-Type": "application/json"
        },
        json={"amount": 450.00, "currency": "USD", "recipient_id": "vendor_corp_99"}
    )
    print(f"  [POST /api/v1/payments] Status: {res3.status_code} - Discovered /api/v1/payments")

    # 2. Shadow APIs Discovery
    log_step("Phase 2: Probing Undocumented / Shadow API Endpoints (Exactly 2)")
    
    # Shadow API #1: System Debug Dump
    res_shadow1 = requests.get(
        f"{BASE_URL}/api/v2/debug",
        headers={"X-Forwarded-For": "203.0.113.88"}
    )
    print(f"  [GET /api/v2/debug] Status: {res_shadow1.status_code} -> FLAG AS SHADOW API #1 (Unauthenticated, leaks env secrets)")

    # Shadow API #2: Legacy Admin Export
    res_shadow2 = requests.get(
        f"{BASE_URL}/api/v1/admin/export",
        headers={"X-Forwarded-For": "198.51.100.99"}
    )
    print(f"  [GET /api/v1/admin/export] Status: {res_shadow2.status_code} -> FLAG AS SHADOW API #2 (Unmanaged PII Data Dump)")

    # 3. Runtime Abuse Heuristic 1: BOLA Attack (Cross-User Unauthorized Access)
    log_step("Phase 3: Triggering Abuse Scenario 1 - BOLA (Broken Object Level Authorization)")
    print("  Attacker session 'user_101' targeting 'user_202' and 'user_303' balances...")
    
    bola_res1 = requests.get(
        f"{BASE_URL}/api/v1/users/user_202/balance",
        headers={
            "Authorization": "Bearer token_usr_101_legit",
            "X-User-Id": "user_101",  # Session ID mismatch!
            "X-Forwarded-For": "45.33.32.156"
        }
    )
    print(f"  [BOLA Access 1] Accessing user_202 balance with user_101 session: Status {bola_res1.status_code}")

    bola_res2 = requests.get(
        f"{BASE_URL}/api/v1/users/user_303",
        headers={
            "Authorization": "Bearer token_usr_101_legit",
            "X-User-Id": "user_101",  # Session ID mismatch!
            "X-Forwarded-For": "45.33.32.156"
        }
    )
    print(f"  [BOLA Access 2] Accessing user_303 profile with user_101 session: Status {bola_res2.status_code}")

    # 4. Runtime Abuse Heuristic 2: Token Replay (> 2 Distinct IPs using identical Bearer token)
    log_step("Phase 4: Triggering Abuse Scenario 2 - Token Replay Attack")
    shared_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.stolen_compromised_session_token"
    replay_ips = ["198.51.100.12", "203.0.113.44", "192.0.2.89", "104.28.19.4"]
    
    print(f"  Replaying single token '{shared_token[:20]}...' concurrently across {len(replay_ips)} IPs...")
    for ip in replay_ips:
        r = requests.get(
            f"{BASE_URL}/api/v1/users/user_101",
            headers={
                "Authorization": f"Bearer {shared_token}",
                "X-User-Id": "user_101",
                "X-Forwarded-For": ip
            }
        )
        print(f"    Origin IP: {ip} -> Request dispatched (Status {r.status_code})")
        time.sleep(0.1)

    # 5. Runtime Abuse Heuristic 3: Burst Scraping Anomaly (> 15 requests in 10s window)
    log_step("Phase 5: Triggering Abuse Scenario 3 - High-Frequency Scraping Anomaly")
    scraper_ip = "185.220.101.5"
    burst_count = 18
    print(f"  Firing rapid burst of {burst_count} requests within 2 seconds from IP: {scraper_ip}...")
    for i in range(burst_count):
        requests.get(
            f"{BASE_URL}/api/v1/users/user_101",
            headers={
                "X-Forwarded-For": scraper_ip,
                "User-Agent": "BotScraper/3.1 (Automated; DataHarvest)"
            }
        )
    print(f"  ✔ Burst completed: {burst_count} requests dispatched from {scraper_ip}.")

    # 6. Verify System Telemetry & Pass/Fail Criteria
    time.sleep(0.5)
    log_step("Phase 6: Verifying Telemetry & Pass/Fail Acceptance Criteria")
    kpis = requests.get(f"{BASE_URL}/api/governance/kpis").json()
    inventory = requests.get(f"{BASE_URL}/api/governance/inventory").json()
    alerts = requests.get(f"{BASE_URL}/api/governance/alerts").json()

    print("\n--- KPI METRICS REPORT ---")
    print(f"  Total Endpoints Discovered : {kpis['total_apis']}")
    print(f"  Shadow Endpoints Flagged   : {kpis['shadow_apis']} (Target: 2)")
    print(f"  Active Security Alerts     : {kpis['active_alerts']}")
    print(f"  Average Risk Score         : {kpis['avg_risk_score']} / 100")

    print("\n--- DISCOVERED ENDPOINTS ---")
    shadow_count = 0
    for ep in inventory:
        shadow_tag = "[SHADOW]" if ep["is_shadow"] else "[MANAGED]"
        if ep["is_shadow"]:
            shadow_count += 1
        print(f"  {shadow_tag:9} {ep['method']:6} {ep['endpoint']:28} Risk: {ep['risk_score']:3} ({ep['severity']}) Auth: {ep['auth_type']}")

    print("\n--- DETECTED SECURITY ALERTS ---")
    alert_types_seen = set()
    for a in alerts:
        alert_types_seen.add(a["abuse_type"])
        print(f"  🚨 [{a['severity']:8}] Type: {a['abuse_type']:14} IP: {a['caller_ip']:15} Target: {a['endpoint']}")

    # Verification against criteria
    print("\n=======================================================")
    print("🎯 PASS/FAIL EVALUATION")
    print("=======================================================")
    pass_shadow = (shadow_count == 2)
    pass_bola = "BOLA" in alert_types_seen
    pass_replay = "TOKEN_REPLAY" in alert_types_seen
    pass_scraping = "SCRAPING" in alert_types_seen
    all_passed = pass_shadow and pass_bola and pass_replay and pass_scraping

    print(f"  [Criterion 1] Exactly 2 Shadow APIs flagged    : {'✅ PASS' if pass_shadow else '❌ FAIL'} ({shadow_count}/2)")
    print(f"  [Criterion 2] BOLA Alert Triggered              : {'✅ PASS' if pass_bola else '❌ FAIL'}")
    print(f"  [Criterion 3] Token Replay Alert Triggered      : {'✅ PASS' if pass_replay else '❌ FAIL'}")
    print(f"  [Criterion 4] Scraping Anomaly Triggered        : {'✅ PASS' if pass_scraping else '❌ FAIL'}")
    print(f"  [Criterion 5] Risk Explanations Generated       : {'✅ PASS' if len(inventory) > 0 and len(inventory[0]['risk_reasons']) > 0 else '❌ FAIL'}")

    if all_passed:
        print("\n✨ ALL ACCEPTANCE CRITERIA SATISFIED! Dashboard is fully primed.")
    else:
        print("\n⚠️ Note: Check logs above for any non-passing criteria.")

if __name__ == "__main__":
    run_simulation()
