"""
SecureFlow AI - Prediction API
Endpoints for threat prediction and IOC correlation.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from datetime import datetime
from pydantic import BaseModel
from typing import Optional

router = APIRouter()

_prediction_agent = None
_ioc_agent = None


def get_prediction_agent():
    global _prediction_agent
    if _prediction_agent is None:
        from app.agents.threat_prediction_agent import ThreatPredictionAgent
        _prediction_agent = ThreatPredictionAgent()
    return _prediction_agent


def get_ioc_agent():
    global _ioc_agent
    if _ioc_agent is None:
        from app.agents.ioc_correlation_agent import IOCCorrelationAgent
        _ioc_agent = IOCCorrelationAgent()
    return _ioc_agent


@router.get("/threats")
async def predict_threats(hours: Optional[int] = 24, db: Session = Depends(get_db)):
    """Get threat prediction based on recent alert patterns."""
    from app.models.alert import Alert

    recent_alerts = db.query(Alert).order_by(Alert.created_at.desc()).limit(50).all()
    alert_dicts = [
        {
            "id": a.id,
            "title": a.title,
            "severity": a.severity,
            "source_ip": a.source_ip,
            "mitre_technique": a.mitre_technique,
            "mitre_tactic": getattr(a, "mitre_tactic", None),
        }
        for a in recent_alerts
    ]

    agent = get_prediction_agent()
    return agent.predict_next_attack(alert_dicts, time_window_hours=hours)


@router.get("/threats/history")
async def get_prediction_history():
    """Get historical prediction trend data."""
    agent = get_prediction_agent()
    return {"history": agent.get_prediction_history()}


@router.post("/ioc/correlate/{alert_id}")
async def correlate_alert_iocs(alert_id: int, db: Session = Depends(get_db)):
    """Run IOC correlation analysis on a specific alert."""
    from app.models.alert import Alert
    from fastapi import HTTPException

    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    recent = db.query(Alert).order_by(Alert.created_at.desc()).limit(20).all()

    alert_dict = {
        "id": alert.id,
        "title": alert.title,
        "severity": alert.severity,
        "source_ip": alert.source_ip,
        "description": alert.description,
        "mitre_technique": alert.mitre_technique,
    }
    recent_dicts = [{"title": a.title, "source_ip": a.source_ip} for a in recent]

    agent = get_ioc_agent()
    return agent.correlate_alert(alert_dict, recent_dicts)


@router.get("/ioc/campaigns")
async def get_campaigns():
    """Get list of correlated threat campaigns."""
    agent = get_ioc_agent()
    return {
        "campaigns": agent.get_correlated_campaigns(),
        "known_iocs": agent.get_all_known_iocs(),
    }


@router.post("/ioc/enrich")
async def enrich_ioc(ioc_type: str, ioc_value: str):
    """Enrich a single IOC against threat intelligence."""
    agent = get_ioc_agent()
    return agent.enrich_ioc(ioc_type, ioc_value)
