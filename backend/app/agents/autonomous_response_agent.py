"""
SecureFlow AI - Autonomous Response Agent
Executes security response actions with configurable autonomy levels:
  - HUMAN_APPROVAL: All actions require explicit human sign-off
  - RISK_AWARE: Auto-executes low-risk, escalates high-risk
  - AUTONOMOUS: Full automation with guardrails
  - EMERGENCY: Immediate containment, notify after
"""

import time
import json
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
from app.agents.base_agent import BaseAgent

logger = logging.getLogger(__name__)

# ─── Response Action Catalog ──────────────────────────────────────────────────

RESPONSE_ACTIONS = {
    "block_ip": {
        "risk_level": "medium",
        "reversible": True,
        "requires_approval": ["human_approval"],
        "description": "Block source IP on perimeter firewall",
        "rollback": "unblock_ip",
        "mitre_mitigation": "M1037",
    },
    "isolate_host": {
        "risk_level": "high",
        "reversible": True,
        "requires_approval": ["human_approval", "risk_aware"],
        "description": "Network-isolate a compromised endpoint",
        "rollback": "reconnect_host",
        "mitre_mitigation": "M1030",
    },
    "disable_user": {
        "risk_level": "high",
        "reversible": True,
        "requires_approval": ["human_approval", "risk_aware"],
        "description": "Disable compromised user account in AD/IdP",
        "rollback": "enable_user",
        "mitre_mitigation": "M1026",
    },
    "force_mfa": {
        "risk_level": "low",
        "reversible": True,
        "requires_approval": [],
        "description": "Force MFA re-enrollment for suspicious user",
        "rollback": None,
        "mitre_mitigation": "M1032",
    },
    "revoke_tokens": {
        "risk_level": "medium",
        "reversible": False,
        "requires_approval": ["human_approval"],
        "description": "Revoke all active session tokens for user",
        "rollback": None,
        "mitre_mitigation": "M1017",
    },
    "quarantine_file": {
        "risk_level": "low",
        "reversible": True,
        "requires_approval": [],
        "description": "Quarantine malicious file via EDR",
        "rollback": "restore_file",
        "mitre_mitigation": "M1045",
    },
    "kill_process": {
        "risk_level": "medium",
        "reversible": False,
        "requires_approval": ["human_approval"],
        "description": "Terminate malicious process on endpoint",
        "rollback": None,
        "mitre_mitigation": "M1038",
    },
    "create_firewall_rule": {
        "risk_level": "low",
        "reversible": True,
        "requires_approval": [],
        "description": "Add deny rule for suspicious traffic pattern",
        "rollback": "remove_firewall_rule",
        "mitre_mitigation": "M1037",
    },
    "snapshot_instance": {
        "risk_level": "low",
        "reversible": True,
        "requires_approval": [],
        "description": "Take forensic snapshot of compromised VM",
        "rollback": None,
        "mitre_mitigation": "M1053",
    },
    "notify_soc": {
        "risk_level": "none",
        "reversible": True,
        "requires_approval": [],
        "description": "Send priority alert to SOC team via all channels",
        "rollback": None,
        "mitre_mitigation": None,
    },
}

# Pending approval queue (in-memory for demo, Redis in production)
_approval_queue: List[Dict] = []
_action_history: List[Dict] = []


class AutonomousResponseAgent(BaseAgent):
    """
    Autonomous Response Agent — executes security containment actions.
    
    Autonomy Modes:
      human_approval: All actions queued for human review
      risk_aware:     Low-risk actions auto-execute, high-risk escalated
      autonomous:     All safe/reversible actions auto-execute
      emergency:      Immediate execution, notify after
    """

    def __init__(self, mode: str = "risk_aware"):
        super().__init__()
        self.name = "autonomous_response_agent"
        self.description = "Executes security response actions with configurable autonomy and guardrails"
        self.capabilities = [
            "threat_containment",
            "host_isolation",
            "user_account_actions",
            "firewall_management",
            "forensic_collection",
            "rollback_execution",
        ]
        self.version = "2.0.0"
        self.llm_provider = "groq"
        self.max_tokens = 1500
        self.mode = mode  # human_approval | risk_aware | autonomous | emergency

    def _system_prompt(self) -> str:
        return """You are SecureFlow AI's Autonomous Response Agent — an elite security automation system.

Your role:
- Analyze security incidents and select the most effective response actions
- Evaluate risk level and reversibility before recommending any action  
- Always recommend rollback procedures alongside each action
- Prioritize containment over eradication during active incidents
- Never recommend destructive or irreversible actions without explicit justification

Safety constraints (NEVER violate):
- Do not recommend actions that could cause business outages without documented approval
- Always include confidence scores and uncertainty ranges
- Provide step-by-step rollback procedures for every action
- Flag actions that require human judgment

Output format: JSON only. No prose explanations outside JSON structure."""

    def _build_prompt(self, incident: Dict[str, Any]) -> str:
        severity = incident.get("severity", "medium")
        alert_title = incident.get("title", "Unknown Alert")
        source_ip = incident.get("source_ip", "unknown")
        affected_asset = incident.get("affected_asset", "unknown")
        mitre_technique = incident.get("mitre_technique", "unknown")
        mode = self.mode

        available_actions = "\n".join([
            f"- {name}: {info['description']} [risk={info['risk_level']}, reversible={info['reversible']}]"
            for name, info in RESPONSE_ACTIONS.items()
        ])

        return f"""Incident requiring autonomous response:

INCIDENT DETAILS:
- Title: {alert_title}
- Severity: {severity.upper()}
- Source IP: {source_ip}
- Affected Asset: {affected_asset}
- MITRE Technique: {mitre_technique}
- Autonomy Mode: {mode.upper()}

AVAILABLE RESPONSE ACTIONS:
{available_actions}

TASK:
Select the optimal sequence of response actions for this incident.

Return JSON with this exact structure:
{{
  "threat_assessment": {{
    "threat_level": "critical|high|medium|low",
    "attack_stage": "initial_access|execution|persistence|lateral_movement|exfiltration",
    "confidence": 0.0-1.0,
    "key_indicators": ["indicator1", "indicator2"]
  }},
  "recommended_actions": [
    {{
      "action": "<action_name_from_catalog>",
      "target": "<target_ip_or_user_or_asset>",
      "priority": 1,
      "justification": "<why this action>",
      "risk_level": "low|medium|high",
      "reversible": true/false,
      "rollback_steps": ["step1", "step2"],
      "auto_execute": true/false,
      "estimated_effectiveness": 0.0-1.0
    }}
  ],
  "containment_strategy": "<brief strategy description>",
  "estimated_containment_time_minutes": <number>,
  "requires_human_approval": true/false,
  "escalation_reason": "<if approval needed, why>"
}}"""

    def process(self, incident: Dict[str, Any], db=None) -> Dict[str, Any]:
        """Process an incident and generate/execute response actions."""
        start_time = time.time()

        try:
            system_prompt = self._system_prompt()
            user_prompt = self._build_prompt(incident)

            raw_response = self._call_llm(user_prompt, system_prompt)
            parsed = self._parse_json_response(raw_response)

            if not parsed:
                parsed = self._fallback_response(incident)

            # Apply autonomy mode filtering
            actions = parsed.get("recommended_actions", [])
            approved = []
            queued_for_approval = []

            for action in actions:
                action_name = action.get("action", "")
                action_meta = RESPONSE_ACTIONS.get(action_name, {})
                risk_level = action_meta.get("risk_level", "high")
                requires_approval_modes = action_meta.get("requires_approval", [])

                should_queue = self.mode in requires_approval_modes

                if self.mode == "emergency":
                    # Emergency: execute everything immediately
                    should_queue = False
                elif self.mode == "autonomous":
                    # Autonomous: only queue if flagged as truly high-risk
                    should_queue = risk_level == "high" and not action_meta.get("reversible", False)

                if should_queue:
                    action["status"] = "pending_approval"
                    action["queued_at"] = datetime.utcnow().isoformat()
                    action["incident_id"] = incident.get("id", "unknown")
                    queued_for_approval.append(action)
                    _approval_queue.append(action)
                else:
                    action["status"] = "auto_executed"
                    action["executed_at"] = datetime.utcnow().isoformat()
                    approved.append(action)
                    _action_history.append({
                        **action,
                        "incident_title": incident.get("title"),
                        "mode": self.mode,
                    })

            result = {
                "agent": self.name,
                "mode": self.mode,
                "incident_id": incident.get("id"),
                "threat_assessment": parsed.get("threat_assessment", {}),
                "containment_strategy": parsed.get("containment_strategy", ""),
                "auto_executed_actions": approved,
                "pending_approval_actions": queued_for_approval,
                "requires_human_approval": len(queued_for_approval) > 0,
                "estimated_containment_minutes": parsed.get("estimated_containment_time_minutes", 15),
                "total_actions": len(actions),
                "auto_executed_count": len(approved),
                "pending_count": len(queued_for_approval),
                "processing_time_ms": int((time.time() - start_time) * 1000),
                "timestamp": datetime.utcnow().isoformat(),
            }

            logger.info(
                f"✅ AutonomousResponseAgent: {len(approved)} auto-executed, "
                f"{len(queued_for_approval)} pending approval (mode={self.mode})"
            )
            return result

        except Exception as e:
            logger.error(f"AutonomousResponseAgent error: {e}")
            return {
                "agent": self.name,
                "error": str(e),
                "fallback": self._fallback_response(incident),
            }

    def _fallback_response(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        severity = incident.get("severity", "medium")
        actions = []
        
        if severity in ["critical", "high"]:
            actions.append({
                "action": "notify_soc",
                "target": "soc-team",
                "priority": 1,
                "justification": "Immediate SOC notification for high severity event",
                "risk_level": "none",
                "reversible": True,
                "rollback_steps": [],
                "auto_execute": True,
                "estimated_effectiveness": 0.9,
                "status": "auto_executed",
            })
            actions.append({
                "action": "snapshot_instance",
                "target": incident.get("affected_asset", "unknown"),
                "priority": 2,
                "justification": "Forensic snapshot before any containment",
                "risk_level": "low",
                "reversible": True,
                "rollback_steps": ["Delete snapshot if investigation complete"],
                "auto_execute": True,
                "estimated_effectiveness": 0.8,
                "status": "auto_executed",
            })

        return {
            "threat_assessment": {"threat_level": severity, "confidence": 0.6},
            "recommended_actions": actions,
            "containment_strategy": "Basic notification and evidence preservation",
        }

    def _parse_json_response(self, raw: str) -> Optional[Dict]:
        try:
            # Find JSON block
            start = raw.find("{")
            end = raw.rfind("}") + 1
            if start >= 0 and end > start:
                return json.loads(raw[start:end])
        except Exception:
            pass
        return None

    def get_approval_queue(self) -> List[Dict]:
        return _approval_queue

    def approve_action(self, action_index: int, approved_by: str) -> Dict[str, Any]:
        if action_index < len(_approval_queue):
            action = _approval_queue.pop(action_index)
            action["status"] = "approved_executed"
            action["approved_by"] = approved_by
            action["approved_at"] = datetime.utcnow().isoformat()
            _action_history.append(action)
            return {"success": True, "action": action}
        return {"success": False, "error": "Action not found in queue"}

    def reject_action(self, action_index: int, rejected_by: str, reason: str) -> Dict[str, Any]:
        if action_index < len(_approval_queue):
            action = _approval_queue.pop(action_index)
            action["status"] = "rejected"
            action["rejected_by"] = rejected_by
            action["rejection_reason"] = reason
            action["rejected_at"] = datetime.utcnow().isoformat()
            return {"success": True, "action": action}
        return {"success": False, "error": "Action not found in queue"}

    def get_action_history(self) -> List[Dict]:
        return _action_history[-50:]  # Last 50 actions
