"""
SecureFlow AI - Compliance Agent
Maps security events to compliance frameworks:
  - NIST Cybersecurity Framework (CSF)
  - CIS Controls v8
  - ISO 27001 (reference)
  - SOC 2 Type II (reference)
  
Detects compliance violations, gaps, and generates evidence reports.
"""

import time
import json
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
from app.agents.base_agent import BaseAgent

logger = logging.getLogger(__name__)


# ─── Compliance Framework Mappings ────────────────────────────────────────────

NIST_CSF_MAPPINGS = {
    "brute_force": {
        "function": "Detect",
        "category": "DE.CM-1",
        "subcategory": "The network is monitored to detect potential cybersecurity events",
        "controls": ["DE.CM-1", "PR.AC-7", "RS.AN-1"],
        "violation_type": "Authentication Control Failure",
    },
    "malware": {
        "function": "Detect",
        "category": "DE.CM-4",
        "subcategory": "Malicious code is detected",
        "controls": ["DE.CM-4", "PR.DS-5", "RS.MI-2"],
        "violation_type": "Malware Detection Failure",
    },
    "data_exfiltration": {
        "function": "Protect",
        "category": "PR.DS-5",
        "subcategory": "Protections against data leaks are implemented",
        "controls": ["PR.DS-5", "DE.CM-7", "RS.MI-2"],
        "violation_type": "Data Loss Prevention Failure",
    },
    "unauthorized_access": {
        "function": "Protect",
        "category": "PR.AC-1",
        "subcategory": "Identities and credentials are issued, managed, verified",
        "controls": ["PR.AC-1", "PR.AC-6", "DE.CM-3"],
        "violation_type": "Access Control Violation",
    },
    "vulnerability_exploitation": {
        "function": "Protect",
        "category": "PR.IP-12",
        "subcategory": "A vulnerability management plan is developed and implemented",
        "controls": ["PR.IP-12", "DE.CM-8", "RS.MI-3"],
        "violation_type": "Vulnerability Management Failure",
    },
    "lateral_movement": {
        "function": "Detect",
        "category": "DE.CM-7",
        "subcategory": "Monitoring for unauthorized personnel/connections/devices is performed",
        "controls": ["DE.CM-7", "PR.AC-5", "RS.AN-3"],
        "violation_type": "Network Segmentation Failure",
    },
    "privilege_escalation": {
        "function": "Protect",
        "category": "PR.AC-6",
        "subcategory": "Identities are proofed and bound to credentials",
        "controls": ["PR.AC-6", "PR.AC-4", "DE.CM-3"],
        "violation_type": "Privileged Access Control Failure",
    },
    "insider_threat": {
        "function": "Protect",
        "category": "PR.AC-4",
        "subcategory": "Access permissions and authorizations are managed",
        "controls": ["PR.AC-4", "DE.CM-3", "RS.AN-2"],
        "violation_type": "Insider Threat Control Failure",
    },
}

CIS_CONTROLS_MAPPINGS = {
    "brute_force": {"control_id": "CIS-5", "control_name": "Account Management", "sub_control": "5.4", "level": 1},
    "malware": {"control_id": "CIS-10", "control_name": "Malware Defenses", "sub_control": "10.1", "level": 1},
    "data_exfiltration": {"control_id": "CIS-13", "control_name": "Network Monitoring and Defense", "sub_control": "13.7", "level": 2},
    "unauthorized_access": {"control_id": "CIS-6", "control_name": "Access Control Management", "sub_control": "6.1", "level": 1},
    "vulnerability_exploitation": {"control_id": "CIS-7", "control_name": "Continuous Vulnerability Management", "sub_control": "7.1", "level": 1},
    "lateral_movement": {"control_id": "CIS-12", "control_name": "Network Infrastructure Management", "sub_control": "12.2", "level": 2},
    "privilege_escalation": {"control_id": "CIS-5", "control_name": "Account Management", "sub_control": "5.2", "level": 1},
    "insider_threat": {"control_id": "CIS-3", "control_name": "Data Protection", "sub_control": "3.2", "level": 1},
}

# Detected violations log
_compliance_violations: List[Dict] = []
_compliance_score_history: List[Dict] = []


class ComplianceAgent(BaseAgent):
    """
    Compliance Agent — maps security events to compliance frameworks.
    
    Capabilities:
    - Real-time NIST CSF and CIS Controls violation detection
    - Automated evidence collection from alerts/incidents
    - Compliance score calculation (0-100)
    - Remediation guidance per control
    - Audit-ready report generation
    """

    def __init__(self):
        super().__init__()
        self.name = "compliance_agent"
        self.description = "Maps alerts/incidents to compliance frameworks (NIST CSF, CIS Controls) and detects violations"
        self.capabilities = [
            "nist_csf_mapping",
            "cis_controls_mapping",
            "violation_detection",
            "compliance_scoring",
            "evidence_collection",
            "remediation_guidance",
        ]
        self.version = "1.0.0"
        self.llm_provider = "groq"
        self.max_tokens = 1200

    def _system_prompt(self) -> str:
        return """You are SecureFlow AI's Compliance Agent — a certified compliance and regulatory specialist.

Your expertise:
- NIST Cybersecurity Framework (CSF) 2.0
- CIS Controls v8 (all 18 controls)
- ISO 27001:2022 Annex A
- SOC 2 Type II Trust Service Criteria

Your role:
- Map security events to specific compliance control violations
- Provide remediation guidance aligned to control requirements
- Assess severity of compliance gaps
- Generate audit-ready evidence documentation

Always cite specific control IDs and subcategories.
Output format: JSON only."""

    def analyze_alert_compliance(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a single alert for compliance violations."""
        start_time = time.time()

        alert_type = self._classify_alert_type(alert)
        nist_mapping = NIST_CSF_MAPPINGS.get(alert_type, {})
        cis_mapping = CIS_CONTROLS_MAPPINGS.get(alert_type, {})

        # Build LLM prompt for deep compliance analysis
        prompt = f"""Compliance analysis for security alert:

ALERT DETAILS:
- Title: {alert.get("title", "Unknown")}
- Severity: {alert.get("severity", "medium")}
- Type: {alert_type}
- MITRE Technique: {alert.get("mitre_technique", "N/A")}
- Description: {alert.get("description", "No description")[:300]}

PRE-MAPPED CONTROLS:
- NIST CSF: {json.dumps(nist_mapping)}
- CIS Controls: {json.dumps(cis_mapping)}

TASK: Provide detailed compliance analysis.

Return JSON:
{{
  "violation_confirmed": true/false,
  "violation_severity": "critical|high|medium|low",
  "nist_controls_violated": ["DE.CM-1", "PR.AC-7"],
  "cis_controls_violated": ["CIS-5.4", "CIS-6.1"],
  "iso27001_clauses": ["A.9.4.2", "A.12.6.1"],
  "soc2_criteria": ["CC6.1", "CC7.2"],
  "remediation_steps": [
    "Step 1: Enable account lockout after 5 failed attempts",
    "Step 2: Configure MFA for all privileged accounts"
  ],
  "evidence_items": [
    "Alert log #{alert_id}",
    "Authentication logs from source IP"
  ],
  "regulatory_risk": "audit_finding|reportable_incident|material_breach",
  "compliance_notes": "<audit-ready notes>"
}}"""

        llm_result = {}
        try:
            raw = self._call_llm(prompt, self._system_prompt())
            llm_result = self._parse_json(raw) or {}
        except Exception as e:
            logger.debug(f"ComplianceAgent LLM call failed: {e}")

        violation = {
            "alert_id": alert.get("id"),
            "alert_title": alert.get("title"),
            "alert_type": alert_type,
            "nist_mapping": nist_mapping,
            "cis_mapping": cis_mapping,
            "llm_analysis": llm_result,
            "detected_at": datetime.utcnow().isoformat(),
            "severity": alert.get("severity", "medium"),
            "processing_time_ms": int((time.time() - start_time) * 1000),
        }

        if nist_mapping or llm_result.get("violation_confirmed"):
            _compliance_violations.append(violation)

        return violation

    def get_compliance_score(self, recent_alerts: List[Dict], total_controls: int = 153) -> Dict[str, Any]:
        """Calculate overall compliance posture score."""
        if not recent_alerts:
            return {
                "overall_score": 95,
                "risk_level": "low",
                "controls_violated": 0,
                "total_controls": total_controls,
                "frameworks": {
                    "nist_csf": {"score": 95, "status": "compliant"},
                    "cis_controls": {"score": 96, "status": "compliant"},
                },
                "violations": [],
                "timestamp": datetime.utcnow().isoformat(),
            }

        violated_controls = set()
        violations_by_framework = {"nist": [], "cis": []}

        for alert in recent_alerts:
            alert_type = self._classify_alert_type(alert)
            nist = NIST_CSF_MAPPINGS.get(alert_type, {})
            cis = CIS_CONTROLS_MAPPINGS.get(alert_type, {})

            if nist:
                for ctrl in nist.get("controls", []):
                    violated_controls.add(ctrl)
                violations_by_framework["nist"].append(nist.get("category"))

            if cis:
                violated_controls.add(cis.get("control_id", ""))
                violations_by_framework["cis"].append(cis.get("control_id"))

        critical_alerts = sum(1 for a in recent_alerts if a.get("severity") in ["critical", "high"])
        violation_count = len(violated_controls)

        # Score: start at 100, deduct per violation and severity
        nist_score = max(100 - (violation_count * 5) - (critical_alerts * 3), 0)
        cis_score = max(100 - (violation_count * 4) - (critical_alerts * 2), 0)
        overall = round((nist_score * 0.5 + cis_score * 0.5), 1)

        score_record = {
            "overall_score": overall,
            "timestamp": datetime.utcnow().isoformat(),
        }
        _compliance_score_history.append(score_record)

        return {
            "overall_score": overall,
            "risk_level": self._score_to_risk(overall),
            "controls_violated": violation_count,
            "total_controls": total_controls,
            "frameworks": {
                "nist_csf": {
                    "score": round(nist_score, 1),
                    "status": "compliant" if nist_score >= 80 else "non_compliant",
                    "violated_categories": list(set(violations_by_framework["nist"])),
                },
                "cis_controls": {
                    "score": round(cis_score, 1),
                    "status": "compliant" if cis_score >= 80 else "non_compliant",
                    "violated_controls": list(set(violations_by_framework["cis"])),
                },
            },
            "recent_violations": _compliance_violations[-10:],
            "score_trend": _compliance_score_history[-30:],
            "timestamp": datetime.utcnow().isoformat(),
        }

    def process(self, input_data: Dict[str, Any], db=None) -> Dict[str, Any]:
        task = input_data.get("task", "analyze_alert")
        if task == "compliance_score":
            return self.get_compliance_score(input_data.get("alerts", []))
        elif task == "analyze_alert":
            return self.analyze_alert_compliance(input_data.get("alert", {}))
        else:
            return {"error": f"Unknown task: {task}"}

    def _classify_alert_type(self, alert: Dict[str, Any]) -> str:
        title = (alert.get("title") or "").lower()
        mitre = (alert.get("mitre_technique") or "").lower()
        description = (alert.get("description") or "").lower()
        combined = f"{title} {mitre} {description}"

        if any(kw in combined for kw in ["brute force", "failed login", "password spray", "t1110"]):
            return "brute_force"
        elif any(kw in combined for kw in ["malware", "ransomware", "trojan", "worm", "virus"]):
            return "malware"
        elif any(kw in combined for kw in ["exfil", "data transfer", "upload", "t1041", "t1048"]):
            return "data_exfiltration"
        elif any(kw in combined for kw in ["lateral", "t1021", "t1075", "pivot"]):
            return "lateral_movement"
        elif any(kw in combined for kw in ["privilege", "escalation", "t1068", "t1548"]):
            return "privilege_escalation"
        elif any(kw in combined for kw in ["unauthorized", "access denied", "suspicious login"]):
            return "unauthorized_access"
        elif any(kw in combined for kw in ["cve", "exploit", "vulnerability", "patch"]):
            return "vulnerability_exploitation"
        elif any(kw in combined for kw in ["insider", "off-hours", "unusual behavior"]):
            return "insider_threat"
        return "unauthorized_access"  # Default

    def _score_to_risk(self, score: float) -> str:
        if score >= 90:
            return "minimal"
        elif score >= 75:
            return "low"
        elif score >= 60:
            return "medium"
        elif score >= 40:
            return "high"
        return "critical"

    def _parse_json(self, raw: str) -> Optional[Dict]:
        try:
            start = raw.find("{")
            end = raw.rfind("}") + 1
            if start >= 0 and end > start:
                return json.loads(raw[start:end])
        except Exception:
            pass
        return None
