import os
import sys

# Ensure package path is resolved
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from database.db_client import init_db, upsert_api_inventory, create_alert, reset_db


def seed(reset: bool = True):
    if reset:
        reset_db()
    else:
        init_db()

    # Documented endpoints
    upsert_api_inventory(
        method="GET",
        endpoint="/api/v1/users",
        is_shadow=False,
        risk_score=30,
        reasons=["Documented in OpenAPI", "Public read-only"],
        auth_type="API Key",
        contains_pii=False,
        severity="LOW"
    )
    upsert_api_inventory(
        method="GET",
        endpoint="/api/v1/users/{id}",
        is_shadow=False,
        risk_score=40,
        reasons=["Requires Bearer Authentication", "Contains User Profile PII"],
        auth_type="Bearer Token",
        contains_pii=True,
        severity="MEDIUM"
    )
    upsert_api_inventory(
        method="POST",
        endpoint="/api/v1/payments",
        is_shadow=False,
        risk_score=50,
        reasons=["State-Changing HTTP Method", "Processes Financial PII"],
        auth_type="Bearer Token",
        contains_pii=True,
        severity="MEDIUM"
    )

    # Shadow endpoints with high risk (Exactly 2 shadow endpoints)
    upsert_api_inventory(
        method="GET",
        endpoint="/api/v2/debug",
        is_shadow=True,
        risk_score=90,
        reasons=["Undocumented / Shadow API", "Unauthenticated Public Endpoint", "Processes Sensitive / Confidential Data"],
        auth_type="None",
        contains_pii=True,
        severity="CRITICAL"
    )
    upsert_api_inventory(
        method="DELETE",
        endpoint="/api/v1/admin/users",
        is_shadow=True,
        risk_score=95,
        reasons=["Undocumented / Shadow API", "State-Changing HTTP Method", "Privileged Operation Without Audit"],
        auth_type="None",
        contains_pii=True,
        severity="CRITICAL"
    )

    # Mock security alerts
    create_alert(
        timestamp="2026-10-14T10:00:00Z",
        endpoint="/api/v1/users/{id}",
        alert_type="BOLA",
        severity="HIGH",
        details="User session user_101 attempted to access user_202 profile",
        caller_ip="198.51.100.42"
    )
    create_alert(
        timestamp="2026-10-14T10:05:00Z",
        endpoint="/api/v2/debug",
        alert_type="SHADOW_API",
        severity="CRITICAL",
        details="Undocumented endpoint invoked leaking environment configuration",
        caller_ip="203.0.113.19"
    )

    print("Database seeded successfully with initial baseline.")


if __name__ == "__main__":
    seed()
