from sqlalchemy import Column, Integer, String, Boolean, Text
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class TrafficLogDB(Base):
    __tablename__ = 'traffic_logs'

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(String)
    method = Column(String)
    endpoint = Column(String)
    caller_ip = Column(String)
    token_user_id = Column(String, nullable=True)
    target_resource_id = Column(String, nullable=True)
    payload_size_bytes = Column(Integer, default=0)
    token = Column(String, nullable=True)
    auth_type = Column(String, default="None")
    status_code = Column(Integer, default=200)


class APIEndpointDB(Base):
    __tablename__ = 'api_endpoints'

    id = Column(Integer, primary_key=True, index=True)
    method = Column(String)
    endpoint = Column(String)
    is_shadow = Column(Boolean, default=False)
    risk_score = Column(Integer, default=0)
    risk_reasons = Column(Text)  # JSON string
    alert_count = Column(Integer, default=0)
    auth_type = Column(String, default="None")
    contains_pii = Column(Boolean, default=False)
    total_calls = Column(Integer, default=1)
    severity = Column(String, default="LOW")
    last_seen = Column(String, nullable=True)


class SecurityAlertDB(Base):
    __tablename__ = 'security_alerts'

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(String)
    endpoint = Column(String)
    alert_type = Column(String)  # BOLA, SCRAPING, TOKEN_REPLAY, SHADOW_API
    severity = Column(String)    # LOW, MEDIUM, HIGH, CRITICAL
    caller_ip = Column(String, nullable=True)
    details = Column(Text)
