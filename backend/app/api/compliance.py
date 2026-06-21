"""
SecureFlow AI - Compliance API
Endpoints for compliance framework analysis, scoring, and violations.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from datetime import datetime

router = APIRouter()

_compliance_agent = None

def get_compliance_agent():
    global _compliance_agent
    if _compliance_agent is None:
        from app.agents.compliance_agent import ComplianceAgent
        _compliance_agent = ComplianceAgent()
    return _compliance_agent


@router.get("/score")
async def get_compliance_score(db: Session = Depends(get_db)):
    """Get overall compliance posture score across all frameworks."""
    from app.models.alert import Alert

    recent_alerts = db.query(Alert).filter(Alert.status == "open").limit(50).all()
    alert_dicts = [
        {
            "id": a.id,
            "title": a.title,
            "severity": a.severity,
            "description": a.description,
            "mitre_technique": a.mitre_technique,
        }
        for a in recent_alerts
    ]

    agent = get_compliance_agent()
    return agent.get_compliance_score(alert_dicts)


@router.get("/violations")
async def get_violations():
    """Get list of detected compliance violations."""
    from app.agents.compliance_agent import _compliance_violations
    return {
        "total": len(_compliance_violations),
        "violations": _compliance_violations[-50:],
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.post("/analyze/{alert_id}")
async def analyze_alert_compliance(alert_id: int, db: Session = Depends(get_db)):
    """Analyze a specific alert for compliance violations."""
    from app.models.alert import Alert
    from fastapi import HTTPException

    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert_dict = {
        "id": alert.id,
        "title": alert.title,
        "severity": alert.severity,
        "description": alert.description,
        "mitre_technique": alert.mitre_technique,
    }

    agent = get_compliance_agent()
    return agent.analyze_alert_compliance(alert_dict)


@router.get("/frameworks")
async def get_frameworks():
    """Get supported compliance frameworks and control counts."""
    return {
        "frameworks": [
            {
                "id": "nist_csf",
                "name": "NIST Cybersecurity Framework 2.0",
                "version": "2.0",
                "functions": ["Govern", "Identify", "Protect", "Detect", "Respond", "Recover"],
                "total_subcategories": 106,
                "implemented": True,
            },
            {
                "id": "cis_controls",
                "name": "CIS Controls v8",
                "version": "8.0",
                "total_controls": 18,
                "total_safeguards": 153,
                "implementation_groups": ["IG1", "IG2", "IG3"],
                "implemented": True,
            },
            {
                "id": "iso27001",
                "name": "ISO 27001:2022",
                "version": "2022",
                "total_clauses": 93,
                "implemented": False,
                "roadmap": "Tier 3 - Future Implementation",
            },
            {
                "id": "soc2",
                "name": "SOC 2 Type II",
                "version": "2023",
                "trust_service_criteria": ["CC", "A", "C", "PI", "P"],
                "implemented": False,
                "roadmap": "Tier 3 - Future Implementation",
            },
        ]
    }


@router.get("/controls/nist")
async def get_nist_controls():
    """Get NIST CSF control mappings used by the platform."""
    from app.agents.compliance_agent import NIST_CSF_MAPPINGS
    return {"mappings": NIST_CSF_MAPPINGS, "total": len(NIST_CSF_MAPPINGS)}


@router.get("/controls/cis")
async def get_cis_controls():
    """Get CIS Controls mappings used by the platform."""
    from app.agents.compliance_agent import CIS_CONTROLS_MAPPINGS
    return {"mappings": CIS_CONTROLS_MAPPINGS, "total": len(CIS_CONTROLS_MAPPINGS)}
