"""
SecureFlow AI - Threat Prediction Agent
Uses statistical analysis + LLM reasoning to forecast:
  - Likely next attack vectors
  - Attack progression stages
  - Threat actor intent
  - Time-to-impact predictions
"""

import time
import json
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from collections import Counter
from app.agents.base_agent import BaseAgent

logger = logging.getLogger(__name__)

# MITRE ATT&CK kill chain progression
KILL_CHAIN_PROGRESSION = {
    "initial-access": ["execution", "persistence", "defense-evasion"],
    "execution": ["persistence", "privilege-escalation", "credential-access"],
    "persistence": ["privilege-escalation", "lateral-movement"],
    "privilege-escalation": ["lateral-movement", "credential-access"],
    "defense-evasion": ["execution", "credential-access"],
    "credential-access": ["lateral-movement", "collection"],
    "discovery": ["lateral-movement", "collection"],
    "lateral-movement": ["collection", "exfiltration", "impact"],
    "collection": ["exfiltration", "impact"],
    "command-and-control": ["exfiltration", "impact"],
    "exfiltration": ["impact"],
}

TECHNIQUE_PATTERNS = {
    "T1110": {  # Brute Force
        "next_techniques": ["T1078", "T1021", "T1059"],
        "predicted_tactic": "lateral-movement",
        "time_to_next_hours": 2,
        "confidence": 0.78,
    },
    "T1078": {  # Valid Accounts
        "next_techniques": ["T1021", "T1053", "T1083"],
        "predicted_tactic": "discovery",
        "time_to_next_hours": 4,
        "confidence": 0.82,
    },
    "T1059": {  # Command and Scripting Interpreter
        "next_techniques": ["T1548", "T1053", "T1070"],
        "predicted_tactic": "privilege-escalation",
        "time_to_next_hours": 1,
        "confidence": 0.71,
    },
    "T1190": {  # Exploit Public-Facing Application
        "next_techniques": ["T1059", "T1105", "T1078"],
        "predicted_tactic": "execution",
        "time_to_next_hours": 0.5,
        "confidence": 0.88,
    },
    "T1566": {  # Phishing
        "next_techniques": ["T1059", "T1204", "T1078"],
        "predicted_tactic": "execution",
        "time_to_next_hours": 1,
        "confidence": 0.85,
    },
}

_predictions_history: List[Dict] = []


class ThreatPredictionAgent(BaseAgent):
    """
    Threat Prediction Agent — forecasts next attack steps.
    
    Methodology:
    1. Analyze current attack pattern from recent alerts
    2. Map to MITRE ATT&CK kill chain progression
    3. Statistical likelihood of next techniques
    4. LLM reasoning for context-aware predictions
    5. Time-boxed predictions with confidence intervals
    """

    def __init__(self):
        super().__init__()
        self.name = "threat_prediction_agent"
        self.description = "Predicts next attack vectors using kill chain analysis and ML pattern recognition"
        self.capabilities = [
            "kill_chain_analysis",
            "next_technique_prediction",
            "threat_actor_profiling",
            "time_to_impact_estimation",
            "attack_campaign_forecasting",
        ]
        self.version = "1.0.0"
        self.llm_provider = "groq"
        self.max_tokens = 1200

    def _system_prompt(self) -> str:
        return """You are SecureFlow AI's Threat Prediction Agent — a predictive threat intelligence analyst.

Your methodology:
- Analyze current attack indicators against MITRE ATT&CK kill chain
- Identify patterns consistent with known threat actor TTPs
- Forecast next likely attack stages with probabilistic confidence
- Estimate time windows for predicted activities
- Recommend proactive defensive actions

Important constraints:
- Always express predictions as probability ranges, not certainties
- Cite specific MITRE techniques in predictions
- Provide early warning indicators for each predicted threat
- Focus on actionable intelligence, not theoretical analysis

Output format: JSON only."""

    def predict_next_attack(self, recent_alerts: List[Dict], time_window_hours: int = 24) -> Dict[str, Any]:
        """Predict next attack steps based on recent alert patterns."""
        start_time = time.time()

        if not recent_alerts:
            return self._empty_prediction()

        # ── Statistical analysis ──────────────────────────────────────────────
        mitre_techniques = [a.get("mitre_technique", "") for a in recent_alerts if a.get("mitre_technique")]
        mitre_tactics = [a.get("mitre_tactic", "") for a in recent_alerts if a.get("mitre_tactic")]
        source_ips = [a.get("source_ip", "") for a in recent_alerts if a.get("source_ip")]

        technique_counts = Counter(mitre_techniques)
        tactic_counts = Counter(mitre_tactics)
        ip_counts = Counter(source_ips)

        dominant_technique = technique_counts.most_common(1)[0][0] if technique_counts else None
        dominant_tactic = tactic_counts.most_common(1)[0][0] if tactic_counts else None
        top_source_ips = [ip for ip, _ in ip_counts.most_common(3)]

        # ── Pattern-based prediction ──────────────────────────────────────────
        pattern_predictions = []
        if dominant_technique and dominant_technique in TECHNIQUE_PATTERNS:
            pattern = TECHNIQUE_PATTERNS[dominant_technique]
            for next_tech in pattern.get("next_techniques", []):
                pattern_predictions.append({
                    "technique_id": next_tech,
                    "predicted_tactic": pattern.get("predicted_tactic"),
                    "confidence": pattern.get("confidence", 0.5),
                    "estimated_time_hours": pattern.get("time_to_next_hours", 4),
                    "source": "kill_chain_statistical",
                })

        # Kill chain next stage
        tactic_clean = (dominant_tactic or "").lower().replace(" ", "-")
        next_stages = KILL_CHAIN_PROGRESSION.get(tactic_clean, [])

        # ── LLM reasoning ─────────────────────────────────────────────────────
        llm_prediction = {}
        try:
            alert_summary = [
                {
                    "title": a.get("title"),
                    "severity": a.get("severity"),
                    "mitre_technique": a.get("mitre_technique"),
                    "mitre_tactic": a.get("mitre_tactic"),
                    "source_ip": a.get("source_ip"),
                }
                for a in recent_alerts[-10:]
            ]

            prompt = f"""Threat prediction analysis:

RECENT ALERTS (last {len(recent_alerts)} events):
{json.dumps(alert_summary, indent=2)}

STATISTICAL ANALYSIS:
- Dominant technique: {dominant_technique}
- Dominant tactic: {dominant_tactic}
- Top attacker IPs: {top_source_ips}
- Kill chain next stages: {next_stages}

Predict the next 3-5 attack actions likely to occur in the next {time_window_hours} hours.

Return JSON:
{{
  "threat_assessment": {{
    "current_attack_stage": "<current kill chain stage>",
    "campaign_type": "<opportunistic|targeted|apt>",
    "attacker_sophistication": "low|medium|high|nation_state",
    "estimated_attacker_objective": "<data theft|ransomware|espionage|disruption>",
    "attack_campaign_likelihood": 0.0-1.0
  }},
  "predicted_next_actions": [
    {{
      "rank": 1,
      "technique_id": "T1021",
      "technique_name": "Remote Services",
      "tactic": "lateral-movement",
      "probability": 0.0-1.0,
      "estimated_time_window_hours": <number>,
      "early_warning_indicators": ["indicator1", "indicator2"],
      "recommended_preemptive_actions": ["action1", "action2"]
    }}
  ],
  "hunting_queries": [
    "SELECT * FROM auth_logs WHERE ...",
    "Look for unusual RDP connections from {top_source_ip}"
  ],
  "overall_threat_forecast": "<200 char narrative>",
  "prediction_confidence": 0.0-1.0
}}"""

            raw = self._call_llm(prompt, self._system_prompt())
            llm_prediction = self._parse_json(raw) or {}
        except Exception as e:
            logger.debug(f"ThreatPredictionAgent LLM failed: {e}")

        result = {
            "agent": self.name,
            "analysis_window_hours": time_window_hours,
            "alerts_analyzed": len(recent_alerts),
            "dominant_technique": dominant_technique,
            "dominant_tactic": dominant_tactic,
            "top_source_ips": top_source_ips,
            "kill_chain_next_stages": next_stages,
            "pattern_based_predictions": pattern_predictions,
            "llm_predictions": llm_prediction,
            "threat_level": self._compute_threat_level(recent_alerts),
            "prediction_generated_at": datetime.utcnow().isoformat(),
            "prediction_valid_until": (datetime.utcnow() + timedelta(hours=time_window_hours)).isoformat(),
            "processing_time_ms": int((time.time() - start_time) * 1000),
        }

        _predictions_history.append({
            "threat_level": result["threat_level"],
            "dominant_tactic": dominant_tactic,
            "timestamp": datetime.utcnow().isoformat(),
        })

        return result

    def process(self, input_data: Dict[str, Any], db=None) -> Dict[str, Any]:
        recent_alerts = input_data.get("recent_alerts", [])
        time_window = input_data.get("time_window_hours", 24)
        return self.predict_next_attack(recent_alerts, time_window)

    def _compute_threat_level(self, alerts: List[Dict]) -> str:
        critical = sum(1 for a in alerts if a.get("severity") == "critical")
        high = sum(1 for a in alerts if a.get("severity") == "high")
        if critical >= 3 or (critical >= 1 and high >= 3):
            return "critical"
        elif critical >= 1 or high >= 3:
            return "high"
        elif high >= 1:
            return "medium"
        return "low"

    def _empty_prediction(self) -> Dict[str, Any]:
        return {
            "agent": self.name,
            "alerts_analyzed": 0,
            "threat_level": "minimal",
            "message": "No recent alerts to analyze. System appears to be in normal state.",
            "prediction_generated_at": datetime.utcnow().isoformat(),
        }

    def _parse_json(self, raw: str) -> Optional[Dict]:
        try:
            start = raw.find("{")
            end = raw.rfind("}") + 1
            if start >= 0 and end > start:
                return json.loads(raw[start:end])
        except Exception:
            pass
        return None

    def get_prediction_history(self) -> List[Dict]:
        return _predictions_history[-30:]
