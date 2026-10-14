from dataclasses import dataclass, field
from typing import List, Tuple, Optional


@dataclass
class EndpointContext:
    method: str
    endpoint: str
    is_public: bool = True
    has_authentication: bool = True
    is_shadow: bool = False
    handles_sensitive_data: bool = False
    incident_count_24h: int = 0
    has_bola_alert: bool = False
    has_scraping_alert: bool = False
    has_replay_alert: bool = False


def calculate_endpoint_risk(ctx: EndpointContext) -> Tuple[int, str, List[str]]:
    """
    Calculates a 0-100 explainable risk score for an API endpoint.
    Strictly aligns with the project criteria:
      - Lack of authentication: +25
      - Shadow/Unmanaged status: +35
      - Presence of PII in payload/path: +20
      - Active security alerts (BOLA: +30, Scraping: +15, Replay: +20, incident volume: up to +20)
      - State-changing methods (POST/PUT/DELETE): +10
    """
    score = 0
    reasons = []

    # 1. Shadow / Unmanaged Status (+35)
    if ctx.is_shadow:
        score += 35
        reasons.append("Shadow/Unmanaged status (+35): Endpoint absent from official OpenAPI spec")

    # 2. Lack of Authentication (+25)
    if not ctx.has_authentication or (ctx.is_public and not ctx.has_authentication):
        score += 25
        reasons.append("Lack of authentication (+25): No Authorization header or API key required")

    # 3. Presence of PII / Sensitive data (+20)
    if ctx.handles_sensitive_data:
        score += 20
        reasons.append("Presence of PII in payload/path (+20): Transmits financial or personal identifiers")

    # 4. State-Changing HTTP Method (+10)
    if ctx.method.upper() in ("POST", "PUT", "DELETE", "PATCH"):
        score += 10
        reasons.append(f"State-Changing method (+10): {ctx.method.upper()} mutations alter data state")

    # 5. Active Security Alerts & Breaches
    if ctx.has_bola_alert:
        score += 30
        reasons.append("Active BOLA breach (+30): Broken Object Level Authorization detected")

    if ctx.has_scraping_alert:
        score += 15
        reasons.append("Active Scraping anomaly (+15): High-frequency request burst detected")

    if ctx.has_replay_alert:
        score += 20
        reasons.append("Token Replay alert (+20): Single token observed across multiple IP origins")

    # Incident volume factor (up to 20 pts)
    incident_points = min(ctx.incident_count_24h * 5, 20)
    if incident_points > 0 and not (ctx.has_bola_alert and ctx.has_scraping_alert and ctx.has_replay_alert):
        score += incident_points
        reasons.append(f"Elevated incident volume (+{incident_points}): {ctx.incident_count_24h} incidents recorded")

    # Cap score between 0 and 100
    score = max(0, min(score, 100))

    # Determine severity
    if score <= 30:
        severity = "LOW"
    elif score <= 60:
        severity = "MEDIUM"
    elif score <= 85:
        severity = "HIGH"
    else:
        severity = "CRITICAL"

    if not reasons:
        reasons.append("Clean baseline: Documented endpoint with active authentication")

    return score, severity, reasons


def evaluate_endpoint_from_state(
    method: str,
    endpoint: str,
    auth_type: str,
    is_shadow: bool,
    contains_pii: bool,
    alerts: List[dict]
) -> Tuple[int, str, List[str]]:
    """Helper to evaluate risk score given live runtime parameters and matching alerts."""
    has_auth = auth_type is not None and auth_type.strip().lower() not in ("none", "", "null")
    
    # Filter alerts matching this endpoint
    matching_alerts = [a for a in alerts if a.get("endpoint") == endpoint]
    incident_count = len(matching_alerts)
    has_bola = any("BOLA" in (a.get("alert_type") or "") for a in matching_alerts)
    has_scraping = any("SCRAPING" in (a.get("alert_type") or "") for a in matching_alerts)
    has_replay = any("REPLAY" in (a.get("alert_type") or "") for a in matching_alerts)

    ctx = EndpointContext(
        method=method,
        endpoint=endpoint,
        is_public=True,
        has_authentication=has_auth,
        is_shadow=is_shadow,
        handles_sensitive_data=contains_pii,
        incident_count_24h=incident_count,
        has_bola_alert=has_bola,
        has_scraping_alert=has_scraping,
        has_replay_alert=has_replay
    )
    return calculate_endpoint_risk(ctx)


def reevaluate_inventory_risk(inventory_list: List[dict]) -> List[dict]:
    """
    Takes a list of endpoints from the database (each as a dict),
    runs each through calculate_endpoint_risk, updates their
    risk_score, severity, and risk_reasons, and returns the updated list.
    """
    updated_inventory = []
    for item in inventory_list:
        ctx = EndpointContext(
            method=item.get("method", "GET"),
            endpoint=item.get("endpoint", ""),
            is_public=item.get("is_public", True),
            has_authentication=item.get("has_authentication", True),
            is_shadow=item.get("is_shadow", False),
            handles_sensitive_data=item.get("handles_sensitive_data", item.get("contains_pii", False)),
            incident_count_24h=item.get("incident_count_24h", item.get("alert_count", 0)),
            has_bola_alert=item.get("has_bola_alert", False),
            has_scraping_alert=item.get("has_scraping_alert", False),
            has_replay_alert=item.get("has_replay_alert", False)
        )
        score, severity, reasons = calculate_endpoint_risk(ctx)
        item["risk_score"] = score
        item["severity"] = severity
        item["risk_reasons"] = reasons
        updated_inventory.append(item)
    return updated_inventory


if __name__ == "__main__":
    sample1 = EndpointContext(
        method="GET",
        endpoint="/api/v1/users/{id}",
        is_public=True,
        has_authentication=True,
        is_shadow=False,
        handles_sensitive_data=False,
        incident_count_24h=0,
        has_bola_alert=False,
        has_scraping_alert=False
    )
    score1, level1, reasons1 = calculate_endpoint_risk(sample1)
    print("Sample 1 Documented:", score1, level1, reasons1)

    sample2 = EndpointContext(
        method="GET",
        endpoint="/api/v2/debug",
        is_public=True,
        has_authentication=False,
        is_shadow=True,
        handles_sensitive_data=True
    )
    score2, level2, reasons2 = calculate_endpoint_risk(sample2)
    print("Sample 2 Shadow Debug:", score2, level2, reasons2)
