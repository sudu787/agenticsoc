"""
SecureFlow AI - Risk Scoring API
Endpoints for organizational and alert-level risk scores.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.alert import Alert
from datetime import datetime

router = APIRouter()

_risk_agent = None

def get_risk_agent():
    global _risk_agent
    if _risk_agent is None:
        from app.agents.risk_scoring_agent import RiskScoringAgent
        _risk_agent = RiskScoringAgent()
    return _risk_agent


@router.get("/org")
async def get_org_risk(db: Session = Depends(get_db)):
    """Get organization-wide risk posture score."""
    from app.models.alert import Alert
    from app.models.incident import Incident

    open_alerts = db.query(Alert).filter(Alert.status == "open").all()
    open_incidents = db.query(Incident).filter(Incident.status != "resolved").count()

    critical = sum(1 for a in open_alerts if a.severity == "critical")
    high = sum(1 for a in open_alerts if a.severity == "high")
    medium = sum(1 for a in open_alerts if a.severity == "medium")

    agent = get_risk_agent()
    score = agent.calculate_org_risk_score({
        "critical_alerts": critical,
        "high_alerts": high,
        "medium_alerts": medium,
        "open_incidents": open_incidents,
        "events_today": len(open_alerts),
    })
    return score


@router.get("/trend")
async def get_risk_trend():
    """Get risk score trend data for charts."""
    agent = get_risk_agent()
    return agent.get_risk_trend()


@router.post("/alert/{alert_id}")
async def score_alert(alert_id: int, db: Session = Depends(get_db)):
    """Calculate risk score for a specific alert."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Alert not found")

    all_alerts = db.query(Alert).filter(Alert.status == "open").all()

    alert_dict = {
        "id": alert.id,
        "title": alert.title,
        "severity": alert.severity,
        "source_ip": alert.source_ip,
        "mitre_technique": alert.mitre_technique,
        "mitre_tactic": getattr(alert, "mitre_tactic", None),
        "asset_criticality": "high",
    }
    all_dicts = [{"id": a.id, "source_ip": a.source_ip, "severity": a.severity} for a in all_alerts]

    agent = get_risk_agent()
    return agent.calculate_alert_risk_score(alert_dict, all_dicts)


@router.get("/assets")
async def get_asset_risk(db: Session = Depends(get_db)):
    """Get per-asset risk breakdown."""
    from app.models.alert import Alert
    from collections import defaultdict

    open_alerts = db.query(Alert).filter(Alert.status == "open").all()
    asset_scores = defaultdict(lambda: {"alerts": 0, "critical": 0, "high": 0, "risk_score": 0})

    for alert in open_alerts:
        asset = alert.destination_ip or alert.source_ip or "Unknown Asset"
        asset_scores[asset]["alerts"] += 1
        if alert.severity == "critical":
            asset_scores[asset]["critical"] += 1
            asset_scores[asset]["risk_score"] += 10
        elif alert.severity == "high":
            asset_scores[asset]["high"] += 1
            asset_scores[asset]["risk_score"] += 6

    assets = []
    for asset, data in sorted(asset_scores.items(), key=lambda x: x[1]["risk_score"], reverse=True)[:20]:
        score = min(data["risk_score"], 100)
        assets.append({
            "asset": asset,
            "risk_score": score,
            "risk_level": "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 30 else "low",
            "total_alerts": data["alerts"],
            "critical_alerts": data["critical"],
            "high_alerts": data["high"],
        })

    return {"assets": assets, "total_assets_at_risk": len(assets)}
