from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Text, JSON
from .db import Base

class Event(Base):
    __tablename__ = "events"
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    source = Column(String(50), nullable=False)
    event_type = Column(String(100), nullable=False)
    event_id = Column(String(50), nullable=True)
    username = Column(String(150), nullable=True)
    source_ip = Column(String(100), nullable=True)
    destination_ip = Column(String(100), nullable=True)
    process = Column(String(255), nullable=True)
    command = Column(Text, nullable=True)
    message = Column(Text, nullable=True)
    metadata_json = Column(JSON, default=dict)

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    rule = Column(String(150), nullable=False)
    title = Column(String(255), nullable=False)
    severity = Column(String(30), nullable=False)
    score = Column(Integer, nullable=False)
    status = Column(String(40), default="Open")
    source_ip = Column(String(100), nullable=True)
    username = Column(String(150), nullable=True)
    mitre_technique = Column(String(50), nullable=True)
    mitre_name = Column(String(150), nullable=True)
    evidence = Column(JSON, default=list)

class Incident(Base):
    __tablename__ = "incidents"
    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    title = Column(String(255), nullable=False)
    severity = Column(String(30), nullable=False)
    status = Column(String(40), default="Investigating")
    alert_ids = Column(JSON, default=list)
    notes = Column(Text, default="")
