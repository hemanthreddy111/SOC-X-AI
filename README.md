# SOC-X — AI-Assisted SOC Investigation & Alert Triage Platform

SOC-X is a portfolio-ready SOC analyst lab platform built with FastAPI, SQLite and React/Vite.

## Features
- Security event ingestion
- Rule-based detections: brute force, suspicious PowerShell, port scanning, DNS anomaly, privilege escalation
- Risk/severity scoring
- Alert and incident management
- MITRE ATT&CK mapping
- IOC enrichment demo
- Investigation timeline
- AI-assisted investigation endpoint with deterministic fallback
- React SOC dashboard
- Docker deployment support

## Quick start

### Backend
```bash
cd backend
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

API: http://127.0.0.1:8000/docs

### Frontend
```bash
cd frontend
npm install
npm run dev
```

Open the Vite URL shown in the terminal.

## Demo data
Click **Load Demo Attack** in the dashboard. It creates a realistic brute-force → successful login → PowerShell sequence and runs the detection engine.

## AI configuration
The application works without an AI API by using a deterministic investigation summary. To enable an OpenAI-compatible provider, set:
- `AI_API_KEY`
- `AI_BASE_URL` (optional)
- `AI_MODEL` (optional)

Never commit API keys.

## Production notes
- Set `CORS_ORIGINS` to your deployed frontend URL.
- Use PostgreSQL instead of SQLite for production if needed.
- Do not automatically block real systems from this demo. Response actions are recommendations/analyst workflow records.
