# OUROBOREX

Live threat-intelligence dashboard: map, SignalGraph (Cytoscape), explainable ThreatScore, live events.

## Run (Windows PowerShell)
    cd backend
    pip install -r requirements.txt
    uvicorn main:app --port 8000
    # open http://localhost:8000      (offline? first run:  $env:DEMO=1)

## Test
    pip install -r requirements-dev.txt
    pytest -q tests

## Notes
- Source: abuse.ch Feodo Tracker (keyless). Geolocation: ip-api.com free tier (non-commercial, rate limited).
- Last live data is stored in SQLite and restored on restart (badge shows CACHED until the next pull).
- ThreatScore = 100 x (0.40R + 0.25F + 0.20I + 0.15C), rule-based.
- Not built yet: auth, cases, AI copilot, reports, more connectors, temporal replay, PostgreSQL.
