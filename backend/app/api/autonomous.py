"""
SecureFlow AI - Autonomous Response API
Endpoints for managing the autonomous response agent:
  - Approval queue management
  - Action history
  - Mode switching
  - Manual trigger
"""

from fastapi import APIRouter, HTTPException
from typing import Optional
from pydantic import BaseModel
from datetime import datetime

router = APIRouter()

# Lazy import to avoid circular deps
def _get_agent():
    from app.agents.autonomous_response_agent import AutonomousResponseAgent
    return AutonomousResponseAgent(mode="risk_aware")

_agent_instance = None

def get_agent():
    global _agent_instance
    if _agent_instance is None:
        _agent_instance = _get_agent()
    return _agent_instance


class TriggerRequest(BaseModel):
    incident: dict
    mode: Optional[str] = "risk_aware"  # human_approval | risk_aware | autonomous | emergency


class ApprovalRequest(BaseModel):
    action_index: int
    approved_by: str


class RejectionRequest(BaseModel):
    action_index: int
    rejected_by: str
    reason: str


@router.post("/trigger")
async def trigger_response(req: TriggerRequest):
    """Trigger autonomous response for an incident."""
    agent = get_agent()
    agent.mode = req.mode
    result = agent.process(req.incident)
    return result


@router.get("/queue")
async def get_approval_queue():
    """Get list of actions pending human approval."""
    agent = get_agent()
    queue = agent.get_approval_queue()
    return {
        "pending_count": len(queue),
        "actions": queue,
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.post("/approve")
async def approve_action(req: ApprovalRequest):
    """Approve a pending action."""
    agent = get_agent()
    result = agent.approve_action(req.action_index, req.approved_by)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail="Action not found in queue")
    return result


@router.post("/reject")
async def reject_action(req: RejectionRequest):
    """Reject a pending action."""
    agent = get_agent()
    result = agent.reject_action(req.action_index, req.rejected_by, req.reason)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail="Action not found in queue")
    return result


@router.get("/history")
async def get_action_history():
    """Get history of executed response actions."""
    agent = get_agent()
    history = agent.get_action_history()
    return {
        "total_actions": len(history),
        "actions": history,
    }


@router.get("/catalog")
async def get_action_catalog():
    """Get catalog of available response actions."""
    from app.agents.autonomous_response_agent import RESPONSE_ACTIONS
    return {
        "total_actions": len(RESPONSE_ACTIONS),
        "actions": RESPONSE_ACTIONS,
    }


@router.get("/modes")
async def get_modes():
    """Get available autonomy modes."""
    return {
        "modes": [
            {
                "id": "human_approval",
                "name": "Human Approval",
                "description": "All actions require explicit human sign-off before execution",
                "risk": "lowest",
                "recommended_for": "Regulated environments, production systems",
            },
            {
                "id": "risk_aware",
                "name": "Risk-Aware (Recommended)",
                "description": "Low-risk reversible actions auto-execute; high-risk actions escalated",
                "risk": "balanced",
                "recommended_for": "Standard SOC operations",
            },
            {
                "id": "autonomous",
                "name": "Autonomous",
                "description": "All safe and reversible actions auto-execute without approval",
                "risk": "higher",
                "recommended_for": "High-velocity attack scenarios",
            },
            {
                "id": "emergency",
                "name": "Emergency",
                "description": "Immediate containment of all threats, notify humans after",
                "risk": "highest",
                "recommended_for": "Active ransomware, critical incident response",
            },
        ]
    }
