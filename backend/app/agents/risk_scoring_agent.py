"""
SecureFlow AI - Risk Scoring Agent
Calculates multi-dimensional risk scores for:
  - Individual alerts
  - Assets (devices, users)
  - Organization-wide risk posture
  - Threat trends over time
"""

import time
import json
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
from app.agents.base_agent import BaseAgent

logger = logging.getLogger(__name__)


# ─── Risk Scoring Configuration ───────────────────────────────────────────────

SEVERITY_WEIGHTS = {
    "critical": 10.0,
    "high": 7.5,
    "medium": 4.0,
    "low": 1.5,
    "info": 0.5,
}

MITRE_TACTIC_WEIGHTS = {
    "initial-access": 6.0,
    "execution": 7.0,
    "persistence": 8.0,
    "privilege-escalation": 9.0,
    "defense-evasion": 8.5,
    "credential-access": 9.0,
    "discovery": 5.0,
    "lateral-movement": 9.5,
    "collection": 7.0,
    "exfiltration": 10.0,
    "impact": 10.0,
    "command-and-control": 8.0,
    "reconnaissance": 4.0,
    "resource-development": 3.0,
}

ASSET_CRITICALITY_MULTIPLIERS = {
    "critical": 2.5,
    "high": 1.8,
    "medium": 1.2,
    "low": 0.8,
    "unknown": 1.0,
}

# Risk history for trend analysis (in-memory)
_risk_history: List[Dict] = []


class RiskScoringAgent(BaseAgent):
    """
    Risk Scoring Agent — quantifies organizational security risk.
    
    Scoring dimensions:
    1. Alert severity × MITRE tactic weight
    2. Asset criticality multiplier
    3. Velocity score (alert frequency spike)
    4. Correlation score (multi-alert campaign detection)
    5. LLM-assessed contextual risk
    """

    def __init__(self):
        super().__init__()
        self.name = "risk_scoring_agent"
        self.description = "Multi-dimensional risk scoring for alerts, assets, and organizational posture"
        self.capabilities = [
            "alert_risk_scoring",
            "asset_risk_assessment",
            "org_risk_posture",
            "risk_trend_analysis",
            "threat_campaign_detection",
        ]
        self.version = "1.0.0"
        self.llm_provider = "groq"
        self.max_tokens = 1000

    def _system_prompt(self) -> str:
        return """You are SecureFlow AI's Risk Scoring Agent — a quantitative cybersecurity risk analyst.

Your role:
- Assess contextual risk factors that cannot be computed algorithmically
- Evaluate threat actor sophistication and campaign coordination
- Consider business context (time of day, asset criticality, user role)
- Identify risk amplifiers (e.g., unpatched CVE + active exploitation)
- Provide a numerical risk adjustment in range [-20, +30]

Output format: JSON only."""

    def calculate_alert_risk_score(self, alert: Dict[str, Any], all_alerts: List[Dict] = None) -> Dict[str, Any]:
        """Calculate a comprehensive risk score for a single alert."""
        start_time = time.time()

        severity = alert.get("severity", "medium").lower()
        mitre_tactic = (alert.get("mitre_tactic") or "").lower().replace(" ", "-")
        asset_criticality = alert.get("asset_criticality", "unknown").lower()
        source_ip = alert.get("source_ip", "")

        # ── Base score from severity ──────────────────────────────────────────
        base_score = SEVERITY_WEIGHTS.get(severity, 4.0)

        # ── MITRE tactic weighting ────────────────────────────────────────────
        tactic_weight = MITRE_TACTIC_WEIGHTS.get(mitre_tactic, 5.0)
        tactic_score = (base_score * tactic_weight) / 10.0

        # ── Asset criticality multiplier ──────────────────────────────────────
        criticality_mult = ASSET_CRITICALITY_MULTIPLIERS.get(asset_criticality, 1.0)

        # ── Velocity score (same IP/user recently?) ───────────────────────────
        velocity_score = 0.0
        if all_alerts and source_ip:
            recent_from_same_ip = sum(
                1 for a in all_alerts
                if a.get("source_ip") == source_ip and a.get("id") != alert.get("id")
            )
            velocity_score = min(recent_from_same_ip * 2.5, 15.0)

        # ── Raw computed score ────────────────────────────────────────────────
        raw_score = (tactic_score * criticality_mult) + velocity_score
        raw_score = min(raw_score, 70.0)  # Cap before LLM adjustment

        # ── LLM contextual adjustment ─────────────────────────────────────────
        llm_adjustment = 0.0
        try:
            prompt = f"""Alert risk assessment:
- Title: {alert.get("title", "Unknown")}
- Severity: {severity}
- MITRE Technique: {alert.get("mitre_technique", "unknown")}
- MITRE Tactic: {mitre_tactic}
- Source IP: {source_ip}
- Affected Asset: {alert.get("affected_asset", "unknown")} (criticality: {asset_criticality})
- Recent similar alerts from same source: {int(velocity_score/2.5)}
- Current computed risk score: {raw_score:.1f}/70

Analyze any contextual risk factors and provide an adjustment.

Return JSON:
{{
  "adjustment": <-20 to +30>,
  "risk_amplifiers": ["factor1", "factor2"],
  "risk_reducers": ["factor1"],
  "threat_sophistication": "opportunistic|targeted|nation_state",
  "attack_campaign_likelihood": 0.0-1.0,
  "recommended_priority": "immediate|high|standard|monitor",
  "analyst_notes": "<brief notes>"
}}"""

            raw_llm = self._call_llm(prompt, self._system_prompt())
            llm_data = self._parse_json(raw_llm)
            if llm_data:
                llm_adjustment = float(llm_data.get("adjustment", 0))
        except Exception as e:
            logger.debug(f"LLM risk adjustment skipped: {e}")
            llm_data = {}

        # ── Final score (0-100 scale) ─────────────────────────────────────────
        final_score = min(max(raw_score + llm_adjustment, 0), 100)
        risk_level = self._score_to_level(final_score)

        result = {
            "alert_id": alert.get("id"),
            "risk_score": round(final_score, 1),
            "risk_level": risk_level,
            "score_breakdown": {
                "severity_base": round(base_score, 1),
                "tactic_weighted": round(tactic_score, 1),
                "criticality_multiplier": criticality_mult,
                "velocity_bonus": round(velocity_score, 1),
                "llm_contextual_adjustment": round(llm_adjustment, 1),
            },
            "threat_assessment": llm_data if llm_data else {
                "threat_sophistication": "unknown",
                "attack_campaign_likelihood": 0.5,
                "recommended_priority": risk_level,
            },
            "processing_time_ms": int((time.time() - start_time) * 1000),
            "scored_at": datetime.utcnow().isoformat(),
        }

        # Store for trend analysis
        _risk_history.append({
            "score": final_score,
            "level": risk_level,
            "timestamp": datetime.utcnow().isoformat(),
        })

        return result

    def calculate_org_risk_score(self, stats: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate organization-wide risk posture score."""
        open_critical = stats.get("critical_alerts", 0)
        open_high = stats.get("high_alerts", 0)
        open_medium = stats.get("medium_alerts", 0)
        open_incidents = stats.get("open_incidents", 0)
        events_today = stats.get("events_today", 0)

        # Weighted alert score
        alert_score = (
            (open_critical * 10) +
            (open_high * 6) +
            (open_medium * 2)
        )
        alert_score = min(alert_score, 60)

        # Incident pressure
        incident_score = min(open_incidents * 8, 25)

        # Activity spike (high volume = higher risk)
        activity_score = min(events_today / 100, 15)

        total = min(alert_score + incident_score + activity_score, 100)
        total = max(total, 0)

        level = self._score_to_level(total)

        return {
            "org_risk_score": round(total, 1),
            "risk_level": level,
            "breakdown": {
                "alert_pressure": round(alert_score, 1),
                "incident_pressure": round(incident_score, 1),
                "activity_anomaly": round(activity_score, 1),
            },
            "open_critical_alerts": open_critical,
            "open_incidents": open_incidents,
            "recommendation": self._risk_recommendation(level),
            "timestamp": datetime.utcnow().isoformat(),
        }

    def process(self, input_data: Dict[str, Any], db=None) -> Dict[str, Any]:
        """Route to appropriate scoring method based on input type."""
        task = input_data.get("task", "alert_risk")
        if task == "org_risk":
            return self.calculate_org_risk_score(input_data.get("stats", {}))
        else:
            return self.calculate_alert_risk_score(
                input_data.get("alert", {}),
                input_data.get("all_alerts", [])
            )

    def _score_to_level(self, score: float) -> str:
        if score >= 80:
            return "critical"
        elif score >= 60:
            return "high"
        elif score >= 35:
            return "medium"
        elif score >= 15:
            return "low"
        return "minimal"

    def _risk_recommendation(self, level: str) -> str:
        recommendations = {
            "critical": "Immediate SOC activation required. Escalate to CISO and activate incident response plan.",
            "high": "Priority investigation required within 1 hour. Assign senior analyst.",
            "medium": "Standard investigation SLA (4 hours). Assign available analyst.",
            "low": "Monitor and log. Review during next scheduled triage cycle.",
            "minimal": "No immediate action required. Continue standard monitoring.",
        }
        return recommendations.get(level, "Review at next scheduled cycle.")

    def _parse_json(self, raw: str) -> Optional[Dict]:
        try:
            start = raw.find("{")
            end = raw.rfind("}") + 1
            if start >= 0 and end > start:
                return json.loads(raw[start:end])
        except Exception:
            pass
        return None

    def get_risk_trend(self) -> Dict[str, Any]:
        """Return risk score trend data for charts."""
        if not _risk_history:
            return {"trend": [], "average": 0, "peak": 0}
        recent = _risk_history[-100:]
        scores = [r["score"] for r in recent]
        return {
            "trend": recent,
            "average": round(sum(scores) / len(scores), 1),
            "peak": round(max(scores), 1),
            "current": round(scores[-1], 1) if scores else 0,
        }
