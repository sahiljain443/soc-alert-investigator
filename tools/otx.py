"""AlienVault OTX (Open Threat Exchange) API client."""

import httpx
from typing import Any, Dict, List, Optional


class OTXClient:
    """
    Client for AlienVault OTX API.

    OTX provides:
    - IP reputation and geo data
    - Domain analysis
    - URL scanning
    - File hash lookups
    - Pulses (community threat reports)
    - Related indicators
    """

    BASE_URL = "https://otx.alienvault.com/api/v1"

    def __init__(self, api_key: str):
        """
        Initialize OTX client.

        Args:
            api_key: OTX API key
        """
        self.api_key = api_key
        self.headers = {
            "X-OTX-API-KEY": api_key,
            "Accept": "application/json",
        }

    async def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """
        Look up an IP address in OTX.

        Args:
            ip: IP address to look up

        Returns:
            OTX indicator data including pulses and geo info
        """
        async with httpx.AsyncClient() as client:
            # Get general info
            response = await client.get(
                f"{self.BASE_URL}/indicators/IPv4/{ip}/general",
                headers=self.headers,
                timeout=30.0,
            )
            if response.status_code == 404:
                return {"error": "not_found", "ip": ip}
            response.raise_for_status()
            general = response.json()

            # Get reputation data
            try:
                rep_response = await client.get(
                    f"{self.BASE_URL}/indicators/IPv4/{ip}/reputation",
                    headers=self.headers,
                    timeout=30.0,
                )
                if rep_response.status_code == 200:
                    general["reputation"] = rep_response.json()
            except Exception:
                pass

            # Get malware data
            try:
                mal_response = await client.get(
                    f"{self.BASE_URL}/indicators/IPv4/{ip}/malware",
                    headers=self.headers,
                    timeout=30.0,
                )
                if mal_response.status_code == 200:
                    general["malware"] = mal_response.json()
            except Exception:
                pass

            return general

    async def lookup_domain(self, domain: str) -> Dict[str, Any]:
        """
        Look up a domain in OTX.

        Args:
            domain: Domain to look up

        Returns:
            OTX indicator data
        """
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.BASE_URL}/indicators/domain/{domain}/general",
                headers=self.headers,
                timeout=30.0,
            )
            if response.status_code == 404:
                return {"error": "not_found", "domain": domain}
            response.raise_for_status()
            general = response.json()

            # Get malware data
            try:
                mal_response = await client.get(
                    f"{self.BASE_URL}/indicators/domain/{domain}/malware",
                    headers=self.headers,
                    timeout=30.0,
                )
                if mal_response.status_code == 200:
                    general["malware"] = mal_response.json()
            except Exception:
                pass

            return general

    async def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Look up a file hash in OTX.

        Args:
            file_hash: MD5, SHA1, or SHA256 hash

        Returns:
            OTX file analysis data
        """
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.BASE_URL}/indicators/file/{file_hash}/general",
                headers=self.headers,
                timeout=30.0,
            )
            if response.status_code == 404:
                return {"error": "not_found", "hash": file_hash}
            response.raise_for_status()
            general = response.json()

            # Get analysis data
            try:
                analysis_response = await client.get(
                    f"{self.BASE_URL}/indicators/file/{file_hash}/analysis",
                    headers=self.headers,
                    timeout=30.0,
                )
                if analysis_response.status_code == 200:
                    general["analysis"] = analysis_response.json()
            except Exception:
                pass

            return general

    async def lookup_url(self, url: str) -> Dict[str, Any]:
        """
        Look up a URL in OTX.

        Args:
            url: URL to look up

        Returns:
            OTX URL analysis data
        """
        import base64
        url_id = base64.b64encode(url.encode()).decode()

        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.BASE_URL}/indicators/url/{url_id}/general",
                headers=self.headers,
                timeout=30.0,
            )
            if response.status_code == 404:
                return {"error": "not_found", "url": url}
            response.raise_for_status()
            return response.json()

    def parse_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse OTX response into structured format."""
        if "error" in data:
            return data

        pulse_info = data.get("pulse_info", {})
        pulses = pulse_info.get("pulses", [])

        # Extract pulse tags and names
        pulse_names = [p.get("name", "") for p in pulses[:10]]
        all_tags = []
        for pulse in pulses:
            all_tags.extend(pulse.get("tags", []))
        unique_tags = list(set(all_tags))[:20]

        # Get validation info
        validation = data.get("validation", [])

        return {
            "indicator": data.get("indicator"),
            "type": data.get("type"),
            "pulse_count": pulse_info.get("count", 0),
            "pulse_names": pulse_names,
            "tags": unique_tags,
            "country": data.get("country_name") or data.get("country"),
            "city": data.get("city"),
            "asn": data.get("asn"),
            "validation": validation,
            "reputation": data.get("reputation", {}),
            "malware_samples": len(data.get("malware", {}).get("data", [])),
            "whois": data.get("whois"),
        }

    def get_risk_assessment(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate risk assessment from parsed OTX data.

        Args:
            parsed_data: Parsed lookup response

        Returns:
            Risk assessment with level and reasons
        """
        if "error" in parsed_data:
            return {
                "risk_level": "info",
                "reasons": ["Not found in OTX database"],
                "recommendation": "No OTX threat intelligence available.",
            }

        reasons = []
        risk_level = "info"

        pulse_count = parsed_data.get("pulse_count", 0)
        malware_samples = parsed_data.get("malware_samples", 0)
        tags = parsed_data.get("tags", [])

        # Check pulse count (threat reports mentioning this indicator)
        if pulse_count > 50:
            risk_level = "critical"
            reasons.append(f"CRITICAL: Referenced in {pulse_count} threat pulses")
        elif pulse_count > 20:
            risk_level = "high"
            reasons.append(f"HIGH: Referenced in {pulse_count} threat pulses")
        elif pulse_count > 5:
            risk_level = "medium"
            reasons.append(f"Referenced in {pulse_count} threat pulses")
        elif pulse_count > 0:
            risk_level = "low"
            reasons.append(f"Referenced in {pulse_count} threat pulse(s)")

        # Check for malware associations
        if malware_samples > 10:
            if risk_level in ["info", "low"]:
                risk_level = "high"
            reasons.append(f"Associated with {malware_samples} malware samples")
        elif malware_samples > 0:
            if risk_level == "info":
                risk_level = "medium"
            reasons.append(f"Associated with {malware_samples} malware sample(s)")

        # Check tags for threat indicators
        threat_tags = ["malware", "c2", "botnet", "ransomware", "apt", "phishing", "exploit"]
        found_threat_tags = [t for t in tags if any(tt in t.lower() for tt in threat_tags)]
        if found_threat_tags:
            if risk_level in ["info", "low"]:
                risk_level = "medium"
            reasons.append(f"Threat tags: {', '.join(found_threat_tags[:5])}")

        # Add pulse names if available
        pulse_names = parsed_data.get("pulse_names", [])
        if pulse_names:
            reasons.append(f"Pulses: {', '.join(pulse_names[:3])}{'...' if len(pulse_names) > 3 else ''}")

        if not reasons:
            reasons.append("No significant OTX findings")

        return {
            "risk_level": risk_level,
            "pulse_count": pulse_count,
            "malware_samples": malware_samples,
            "reasons": reasons,
            "recommendation": self._get_recommendation(risk_level, parsed_data),
        }

    def _get_recommendation(self, risk_level: str, parsed_data: Dict[str, Any]) -> str:
        """Get recommendation based on risk level and data."""
        pulse_count = parsed_data.get("pulse_count", 0)
        malware_samples = parsed_data.get("malware_samples", 0)

        if risk_level == "critical":
            return f"CRITICAL: Widely reported threat indicator ({pulse_count} pulses). Block immediately and investigate all connections."
        elif risk_level == "high":
            return f"HIGH RISK: Known threat indicator. Review associated pulses and block if not legitimate."
        elif risk_level == "medium":
            return "MEDIUM RISK: Some threat associations found. Investigate traffic patterns and context."
        elif risk_level == "low":
            return "LOW RISK: Minor threat associations. Monitor but likely benign."
        else:
            return "No significant threat intelligence from OTX."


# Tool definitions for Claude
OTX_TOOLS = [
    {
        "name": "otx_lookup_ip",
        "description": "Look up an IP address in AlienVault OTX for threat pulses, malware associations, and reputation.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip": {
                    "type": "string",
                    "description": "The IP address to look up",
                },
            },
            "required": ["ip"],
        },
    },
    {
        "name": "otx_lookup_domain",
        "description": "Look up a domain in AlienVault OTX for threat pulses and malware associations.",
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "The domain to look up",
                },
            },
            "required": ["domain"],
        },
    },
    {
        "name": "otx_lookup_hash",
        "description": "Look up a file hash (MD5/SHA1/SHA256) in AlienVault OTX for malware analysis.",
        "input_schema": {
            "type": "object",
            "properties": {
                "hash": {
                    "type": "string",
                    "description": "The file hash to look up",
                },
            },
            "required": ["hash"],
        },
    },
]
