"""
SecureFlow AI - IOC Correlation Agent
Enriches and correlates Indicators of Compromise (IOCs) across:
  - Active alerts
  - Security Knowledge Graph
  - Threat intelligence sources
  - MITRE ATT&CK campaigns
"""

import time
import json
import re
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
from app.agents.base_agent import BaseAgent

logger = logging.getLogger(__name__)

# Known malicious IOC database (demo seed data)
_KNOWN_MALICIOUS_IPS = {
    "45.33.32.156": {"threat_actor": "Lazarus Group", "malware": "WannaCry C2", "confidence": 0.95},
    "185.220.101.1": {"threat_actor": "Unknown", "malware": "Tor Exit Node", "confidence": 0.75},
    "91.121.87.18": {"threat_actor": "APT28/Fancy Bear", "malware": "X-Agent", "confidence": 0.88},
    "198.51.100.42": {"threat_actor": "Cozy Bear", "malware": "CosmicDuke", "confidence": 0.82},
    "203.0.113.99": {"threat_actor": "Lazarus Group", "malware": "Destover", "confidence": 0.91},
}

_KNOWN_MALICIOUS_DOMAINS = {
    "evil-update.net": {"threat_actor": "Unknown", "campaign": "Phishing", "confidence": 0.85},
    "malware-cdn.ru": {"threat_actor": "APT29", "campaign": "Supply Chain", "confidence": 0.90},
    "c2-callback.io": {"threat_actor": "FIN7", "campaign": "POS Malware", "confidence": 0.78},
}

_KNOWN_MALICIOUS_HASHES = {
    "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2":
        {"malware_family": "WannaCry", "threat_actor": "Lazarus Group"},
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef":
        {"malware_family": "Emotet", "threat_actor": "TA542"},
}

# Correlated IOC cache
_ioc_correlation_cache: Dict[str, Dict] = {}
_correlated_campaigns: List[Dict] = []


class IOCCorrelationAgent(BaseAgent):
    """
    IOC Correlation Agent — enriches indicators and detects threat campaigns.
    
    Capabilities:
    - Extract IOCs from alert data (IP, domain, hash, email, URL)
    - Match against known threat intelligence
    - Correlate multiple IOCs into campaigns
    - Update Security Knowledge Graph with relationships
    - Calculate IOC confidence scores
    """

    def __init__(self):
        super().__init__()
        self.name = "ioc_correlation_agent"
        self.description = "Extracts, enriches, and correlates IOCs to identify threat campaigns"
        self.capabilities = [
            "ioc_extraction",
            "threat_intel_matching",
            "campaign_correlation",
            "knowledge_graph_update",
            "confidence_scoring",
        ]
        self.version = "1.0.0"
        self.llm_provider = "groq"
        self.max_tokens = 1000

    def _system_prompt(self) -> str:
        return """You are SecureFlow AI's IOC Correlation Agent — a threat intelligence specialist.

Your expertise:
- Identifying and categorizing indicators of compromise (IOCs)
- Correlating IOCs to known threat actors and campaigns
- Assessing IOC reliability and confidence levels
- Mapping IOC clusters to MITRE ATT&CK campaigns

Output format: JSON only. Be precise and concise."""

    def extract_iocs(self, text: str) -> Dict[str, List[str]]:
        """Extract IOCs from raw text using regex patterns."""
        # IP addresses
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ips = re.findall(ip_pattern, text)
        # Filter private IPs
        public_ips = [ip for ip in ips if not (
            ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16.")
        )]

        # Domains
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|de|uk|gov|mil)\b'
        domains = re.findall(domain_pattern, text)

        # File hashes (MD5/SHA256)
        hash_pattern = r'\b[a-fA-F0-9]{32,64}\b'
        hashes = re.findall(hash_pattern, text)

        # Email addresses
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, text)

        # CVE IDs
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cves = re.findall(cve_pattern, text, re.IGNORECASE)

        return {
            "ips": list(set(public_ips))[:10],
            "domains": list(set(domains))[:10],
            "hashes": list(set(hashes))[:5],
            "emails": list(set(emails))[:5],
            "cves": list(set(cves))[:5],
        }

    def enrich_ioc(self, ioc_type: str, ioc_value: str) -> Dict[str, Any]:
        """Look up IOC in threat intelligence database."""
        enrichment = {
            "ioc_type": ioc_type,
            "ioc_value": ioc_value,
            "malicious": False,
            "confidence": 0.0,
            "threat_actor": None,
            "malware_family": None,
            "campaign": None,
            "tlp": "WHITE",
            "sources": ["SecureFlow Internal TI"],
        }

        if ioc_type == "ip" and ioc_value in _KNOWN_MALICIOUS_IPS:
            data = _KNOWN_MALICIOUS_IPS[ioc_value]
            enrichment.update({
                "malicious": True,
                "confidence": data["confidence"],
                "threat_actor": data["threat_actor"],
                "malware_family": data["malware"],
                "tlp": "AMBER",
            })
        elif ioc_type == "domain" and ioc_value in _KNOWN_MALICIOUS_DOMAINS:
            data = _KNOWN_MALICIOUS_DOMAINS[ioc_value]
            enrichment.update({
                "malicious": True,
                "confidence": data["confidence"],
                "threat_actor": data["threat_actor"],
                "campaign": data["campaign"],
                "tlp": "AMBER",
            })
        elif ioc_type == "hash" and ioc_value.lower() in _KNOWN_MALICIOUS_HASHES:
            data = _KNOWN_MALICIOUS_HASHES[ioc_value.lower()]
            enrichment.update({
                "malicious": True,
                "confidence": 0.99,
                "threat_actor": data["threat_actor"],
                "malware_family": data["malware_family"],
                "tlp": "RED",
            })

        return enrichment

    def correlate_alert(self, alert: Dict[str, Any], recent_alerts: List[Dict] = None) -> Dict[str, Any]:
        """Extract IOCs from alert and correlate with threat intelligence."""
        start_time = time.time()

        # Aggregate all text from alert for IOC extraction
        text_blob = " ".join([
            str(alert.get("title", "")),
            str(alert.get("description", "")),
            str(alert.get("source_ip", "")),
            str(alert.get("raw_data", "")),
        ])

        # Also add source_ip directly
        extracted = self.extract_iocs(text_blob)
        if alert.get("source_ip"):
            if alert["source_ip"] not in extracted["ips"]:
                extracted["ips"].append(alert["source_ip"])

        # Enrich all extracted IOCs
        enriched_iocs = []
        malicious_iocs = []

        for ip in extracted.get("ips", []):
            enrichment = self.enrich_ioc("ip", ip)
            enriched_iocs.append(enrichment)
            if enrichment["malicious"]:
                malicious_iocs.append(enrichment)

        for domain in extracted.get("domains", []):
            enrichment = self.enrich_ioc("domain", domain)
            enriched_iocs.append(enrichment)
            if enrichment["malicious"]:
                malicious_iocs.append(enrichment)

        for h in extracted.get("hashes", []):
            enrichment = self.enrich_ioc("hash", h)
            enriched_iocs.append(enrichment)
            if enrichment["malicious"]:
                malicious_iocs.append(enrichment)

        # Detect campaign via LLM if malicious IOCs found
        campaign_analysis = {}
        if malicious_iocs:
            try:
                prompt = f"""Threat campaign correlation analysis:

ALERT: {alert.get("title")} (Severity: {alert.get("severity")})
MITRE Technique: {alert.get("mitre_technique", "unknown")}

MALICIOUS IOCS FOUND:
{json.dumps(malicious_iocs, indent=2)}

RECENT ALERT CONTEXT (last 5):
{json.dumps([{"title": a.get("title"), "source_ip": a.get("source_ip")} for a in (recent_alerts or [])[-5:]], indent=2)}

Analyze if these IOCs are part of a coordinated attack campaign.

Return JSON:
{{
  "campaign_detected": true/false,
  "campaign_name": "<if known, e.g., 'Operation Aurora'>",
  "threat_actor": "<primary threat actor>",
  "attack_stage": "<current stage of attack kill chain>",
  "correlated_techniques": ["T1190", "T1059"],
  "attribution_confidence": 0.0-1.0,
  "recommended_hunting_queries": ["query1", "query2"],
  "ioc_summary": "<brief threat narrative>"
}}"""

                raw = self._call_llm(prompt, self._system_prompt())
                campaign_analysis = self._parse_json(raw) or {}
                if campaign_analysis.get("campaign_detected"):
                    _correlated_campaigns.append({
                        **campaign_analysis,
                        "alert_id": alert.get("id"),
                        "detected_at": datetime.utcnow().isoformat(),
                    })
            except Exception as e:
                logger.debug(f"IOCCorrelationAgent LLM failed: {e}")

        # Build graph update payload
        graph_updates = []
        for ioc in malicious_iocs:
            graph_updates.append({
                "type": "add_ioc",
                "ioc_type": ioc["ioc_type"],
                "ioc_value": ioc["ioc_value"],
                "threat_actor": ioc.get("threat_actor"),
                "malware": ioc.get("malware_family"),
                "alert_id": alert.get("id"),
            })

        result = {
            "agent": self.name,
            "alert_id": alert.get("id"),
            "extracted_iocs": extracted,
            "total_iocs_found": len(enriched_iocs),
            "malicious_iocs": malicious_iocs,
            "malicious_count": len(malicious_iocs),
            "campaign_analysis": campaign_analysis,
            "knowledge_graph_updates": graph_updates,
            "threat_level": "high" if malicious_iocs else "low",
            "processing_time_ms": int((time.time() - start_time) * 1000),
            "timestamp": datetime.utcnow().isoformat(),
        }

        # Cache result
        if alert.get("id"):
            _ioc_correlation_cache[alert["id"]] = result

        return result

    def process(self, input_data: Dict[str, Any], db=None) -> Dict[str, Any]:
        alert = input_data.get("alert", {})
        recent_alerts = input_data.get("recent_alerts", [])
        return self.correlate_alert(alert, recent_alerts)

    def get_correlated_campaigns(self) -> List[Dict]:
        return _correlated_campaigns[-20:]

    def get_all_known_iocs(self) -> Dict[str, Any]:
        return {
            "malicious_ips": list(_KNOWN_MALICIOUS_IPS.keys()),
            "malicious_domains": list(_KNOWN_MALICIOUS_DOMAINS.keys()),
            "total_iocs": len(_KNOWN_MALICIOUS_IPS) + len(_KNOWN_MALICIOUS_DOMAINS) + len(_KNOWN_MALICIOUS_HASHES),
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
