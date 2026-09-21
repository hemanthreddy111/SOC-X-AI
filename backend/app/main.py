import os
from datetime import datetime, timezone
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from .db import Base, engine, get_db
from .models import Event, Alert, Incident
from .schemas import EventIn, AlertOut, IncidentOut
from .detection import detect
from .ai_service import analyze_alert

Base.metadata.create_all(bind=engine)

app = FastAPI(title="SOC-X API", version="1.0.0")
origins = [x.strip() for x in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",") if x.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

@app.get("/")
def root():
    return {"service": "SOC-X API", "status": "ok", "docs": "/docs"}

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "soc-x"}

@app.post("/api/events")
def ingest_event(payload: EventIn, db: Session = Depends(get_db)):
    event = Event(**payload.model_dump())
    if not event.timestamp:
        event.timestamp = datetime.now(timezone.utc)
    db.add(event); db.commit(); db.refresh(event)
    return {"id": event.id, "message": "event ingested"}

@app.post("/api/demo/load")
def load_demo(db: Session = Depends(get_db)):
    from datetime import timedelta
    now = datetime.now(timezone.utc)
    demo = [
        Event(timestamp=now-timedelta(minutes=5), source="windows", event_type="login_failed", event_id="4625", username="administrator", source_ip="10.10.10.50", message="Failed logon"),
        Event(timestamp=now-timedelta(minutes=4), source="windows", event_type="login_failed", event_id="4625", username="administrator", source_ip="10.10.10.50", message="Failed logon"),
        Event(timestamp=now-timedelta(minutes=3), source="windows", event_type="login_failed", event_id="4625", username="administrator", source_ip="10.10.10.50", message="Failed logon"),
        Event(timestamp=now-timedelta(minutes=2), source="windows", event_type="login_failed", event_id="4625", username="administrator", source_ip="10.10.10.50", message="Failed logon"),
        Event(timestamp=now-timedelta(minutes=1), source="windows", event_type="login_failed", event_id="4625", username="administrator", source_ip="10.10.10.50", message="Failed logon"),
        Event(timestamp=now, source="windows", event_type="login_success", event_id="4624", username="administrator", source_ip="10.10.10.50", message="Successful logon"),
        Event(timestamp=now+timedelta(seconds=30), source="windows", event_type="process_start", event_id="4688", username="administrator", source_ip="10.10.10.50", process="powershell.exe", command="powershell.exe -enc UABvAHcAZQByAFMAaABlAGwAbA==", message="PowerShell started"),
    ]
    db.add_all(demo); db.commit()
    created = run_detection(db)
    return {"events_added": len(demo), "alerts_created": created}

@app.post("/api/detect")
def run_detection(db: Session = Depends(get_db)):
    events = db.query(Event).order_by(Event.timestamp.asc()).all()
    payload = [{
        "timestamp": e.timestamp, "event_type": e.event_type, "source_ip": e.source_ip,
        "username": e.username, "process": e.process, "command": e.command,
        "destination_ip": e.destination_ip
    } for e in events]
    found = detect(payload)
    created = 0
    for item in found:
        exists = db.query(Alert).filter(Alert.rule==item["rule"], Alert.source_ip==item["source_ip"], Alert.username==item["username"], Alert.status=="Open").first()
        if exists: continue
        db.add(Alert(**item)); created += 1
    db.commit()
    return {"alerts_created": created}

@app.get("/api/alerts", response_model=list[AlertOut])
def alerts(db: Session = Depends(get_db)):
    return db.query(Alert).order_by(Alert.created_at.desc()).all()

@app.get("/api/alerts/{alert_id}", response_model=AlertOut)
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if not alert: raise HTTPException(404, "Alert not found")
    return alert

@app.post("/api/alerts/{alert_id}/analyze")
async def analyze(alert_id: int, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if not alert: raise HTTPException(404, "Alert not found")
    events = db.query(Event).filter(Event.source_ip == alert.source_ip).order_by(Event.timestamp.asc()).all()
    related = [{"timestamp": e.timestamp.isoformat(), "event_type": e.event_type, "message": e.message, "process": e.process, "command": e.command} for e in events]
    data = {c.name: getattr(alert, c.name) for c in Alert.__table__.columns}
    return await analyze_alert(data, related)

@app.post("/api/incidents", response_model=IncidentOut)
def create_incident(alert_ids: list[int], db: Session = Depends(get_db)):
    alerts_found = [db.get(Alert, i) for i in alert_ids]
    alerts_found = [a for a in alerts_found if a]
    if not alerts_found: raise HTTPException(400, "No valid alerts")
    priority = max(alerts_found, key=lambda a: a.score)
    inc = Incident(title=priority.title, severity=priority.severity, alert_ids=[a.id for a in alerts_found])
    db.add(inc); db.commit(); db.refresh(inc)
    return inc

@app.get("/api/incidents", response_model=list[IncidentOut])
def incidents(db: Session = Depends(get_db)):
    return db.query(Incident).order_by(Incident.created_at.desc()).all()

@app.get("/api/stats")
def stats(db: Session = Depends(get_db)):
    alerts = db.query(Alert).all()
    return {
        "total_alerts": len(alerts),
        "critical": sum(a.severity=="Critical" for a in alerts),
        "high": sum(a.severity=="High" for a in alerts),
        "medium": sum(a.severity=="Medium" for a in alerts),
        "low": sum(a.severity=="Low" for a in alerts),
        "open_incidents": db.query(Incident).filter(Incident.status!="Resolved").count(),
        "events": db.query(Event).count()
    }
