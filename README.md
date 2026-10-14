# sentinel-api
API Security & Governance Command Center
An enterprise-grade API Security & Governance Command Center designed for Security Engineering and DevSecOps teams. The system continuously discovers live API endpoints, flags undocumented shadow routes against an official openapi.json specification, intercepts runtime abuse patterns (BOLA, Scraping, Token Replay), and generates explainable 0–100 risk scoring.

The platform includes a humanized 3D tactile interface built with Three.js (WebGL), Vue 3, and TailwindCSS, featuring real-time telemetry, spatial topology mapping, and tactile hardware-inspired controls.

🏛️ System Architecture
api-security-command-center/
├── backend/
│   ├── app.py                 # FastAPI app + Traffic Interception & Heuristics Middleware
│   ├── openapi.json           # Official OpenAPI 3.0 specification for API catalog
│   ├── database/
│   │   ├── __init__.py
│   │   ├── models.py          # SQLAlchemy SQLite models (TrafficLog, APIEndpoint, SecurityAlert)
│   │   ├── db_client.py       # Thread-safe database operations & query engine
│   │   └── seed.py            # Baseline database seeder
│   └── engine/
│       ├── __init__.py
│       └── risk_scorer.py     # 0-100 Explainable Risk Scoring Engine
├── frontend/
│   └── index.html             # Humanized 3D Command Center SPA (Three.js, Vue 3, Tailwind)
├── simulate.py                # Traffic and attack simulator (Scraping, Token Replay, BOLA)
├── requirements.txt
└── README.md
🚀 Core Features
1. Passive Traffic Interceptor & Discovery Engine
Normalizes dynamic routes in real-time (e.g. /api/v1/users/123/balance ➔ /api/v1/users/{id}/balance).
Inspects authentication headers (Bearer Token, API Key, Basic, None).
Scans query parameters, paths, and JSON payloads for PII (emails, SSNs, credit cards, user identifiers).
Preserves an audit trail of incoming requests with caller IP, session identity, and status code.
2. Shadow API Detector
Cross-references every incoming normalized route and HTTP method against openapi.json.
Flags any uncataloged, undocumented endpoint as "Shadow API" (adds +35 to risk score).
Accurately distinguishes documented core banking routes from legacy or debug endpoints.
3. Runtime Abuse Detection Heuristics
BOLA (Broken Object Level Authorization): Detects when an authenticated user session (X-User-Id or bearer token) requests a private resource belonging to a different resource owner.
Token Replay: Identifies concurrent utilization of an identical authentication token across > 2 distinct IP addresses.
High-Frequency Scraping Anomaly: Sliding window rate monitor that triggers an alert when an IP exceeds 15 requests within a 10-second rolling window.
4. Explainable 0–100 Risk Scoring Engine
Lack of Authentication: +25
Shadow/Unmanaged Status: +35
Presence of PII / Sensitive Data: +20
Active BOLA Breach: +30
Active Scraping Anomaly: +15
Token Replay Breach: +20
State-Changing Methods (POST, PUT, DELETE): +10
Scores are bounded between 0 and 100 with transparent justifications and audit trails.
5. Humanized 3D Tactical Interface
Interactive 3D WebGL API Topology: Three.js spatial visualizer rendering the central API Gateway core, managed endpoints (green dodecahedrons), and unmanaged shadow APIs (pulsing amber/red hazard octahedrons) with attack shockwaves.
Tactile Hardware Aesthetic: Physical beveled cards, directional lighting, deep shadows, and tactile button depression without sterile AI-template clichés.
Integrated Simulation Trigger: One-click "Launch Simulation" button right inside the navbar to trigger simulated attacks with real-time UI updates.
Interactive Risk Inspector: Click any endpoint row or 3D node to view its mathematical score breakdown and cURL reproduction snippet.
⚡ Quick Start
1. Installation
Ensure Python 3.10+ is installed:

cd C:\Users\arvin\.gemini\antigravity\scratch\api-security-command-center
pip install -r requirements.txt
2. Start the Backend & Command Center
Launch the FastAPI server (serves both API and SPA dashboard):

python -m uvicorn app:app --app-dir backend --host 127.0.0.1 --port 8000 --reload
Open your browser to: 👉 http://127.0.0.1:8000

3. Run the Traffic & Attack Simulator
In a separate terminal, execute:

python simulate.py
🧪 Simulation Scenarios & Pass/Fail Criteria
Test Phase	Action	Expected Result	Pass/Fail
Phase 1	Normal traffic to documented endpoints (/users/{id}, /balance, /payments)	Auto-discovered as [MANAGED] with auth requirements	✅ PASS
Phase 2	Probing /api/v2/debug and /api/v1/admin/export	Flagged as exactly 2 Shadow APIs	✅ PASS
Phase 3	Attacker user_101 requesting user_202 and user_303 balance	BOLA Alert triggered (CRITICAL)	✅ PASS
Phase 4	Shared token replayed across 4 distinct IP addresses	TOKEN_REPLAY Alert triggered (HIGH)	✅ PASS
Phase 5	Burst of 18 rapid requests from scraper IP 185.220.101.5	SCRAPING Alert triggered (HIGH)	✅ PASS
Phase 6	Dynamic Risk Scoring & Justifications generation	0–100 Scores with itemized rule justifications	✅ PASS
🛡️ Target Mock Endpoints
Documented Endpoints (in openapi.json)
GET /api/v1/users/{id} — User profile (KYC status, email, tier)
GET /api/v1/users/{id}/balance — Account ledger balance
POST /api/v1/payments — Wire transfer execution
Shadow / Hidden Endpoints (Undocumented)
GET /api/v2/debug — Leaks environment dump and server secret keys
GET /api/v1/admin/export — Unmanaged legacy data dump exposing customer SSNs and emails
