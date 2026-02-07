"""Cisco Talos Intelligence API client for IP and domain reputation."""

import httpx
from typing import Any, Dict, Optional

from models.finding import Finding


class TalosClient:
    """
    Client for Cisco Talos Intelligence.

    Talos provides:
    - IP reputation scores
    - Domain reputation
    - Email reputation
    - Threat categories
    - Blacklist status
    """

    # Talos public reputation lookup (no API key required for basic lookups)
    BASE_URL = "https://talosintelligence.com/cloud_intel"

    # Alternative: Talos API endpoint (requires API access)
    API_URL = "https://api.talos.cisco.com/api/v2"

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize Talos client.

        Args:
            api_key: Optional Talos API key (for full API access)
        """
        self.api_key = api_key
        self.headers = {
            "Accept": "application/json",
            "User-Agent": "SOC-Alert-Investigator/1.0",
        }
        if api_key:
            self.headers["Authorization"] = f"Bearer {api_key}"

    async def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """
        Look up an IP address reputation in Talos.

        Args:
            ip: IP address to look up

        Returns:
            Talos reputation data
        """
        async with httpx.AsyncClient() as client:
            # Try API endpoint first if we have a key
            if self.api_key:
                try:
                    response = await client.get(
                        f"{self.API_URL}/ip/{ip}",
                        headers=self.headers,
                        timeout=30.0,
                    )
                    if response.status_code == 200:
                        return response.json()
                except Exception:
                    pass

            # Fall back to public reputation check
            response = await client.get(
                f"{self.BASE_URL}/ip_reputation",
                params={"ip": ip},
                headers=self.headers,
                timeout=30.0,
            )

            if response.status_code == 404:
                return {"error": "not_found", "ip": ip}

            # Handle different response formats
            try:
                return response.json()
            except Exception:
                # Parse HTML response if JSON not available
                return self._parse_html_response(response.text, ip)

    async def lookup_domain(self, domain: str) -> Dict[str, Any]:
        """
        Look up a domain reputation in Talos.

        Args:
            domain: Domain to look up

        Returns:
            Talos reputation data
        """
        async with httpx.AsyncClient() as client:
            if self.api_key:
                try:
                    response = await client.get(
                        f"{self.API_URL}/domain/{domain}",
                        headers=self.headers,
                        timeout=30.0,
                    )
                    if response.status_code == 200:
                        return response.json()
                except Exception:
                    pass

            # Fall back to public reputation check
            response = await client.get(
                f"{self.BASE_URL}/domain_reputation",
                params={"domain": domain},
                headers=self.headers,
                timeout=30.0,
            )

            if response.status_code == 404:
                return {"error": "not_found", "domain": domain}

            try:
                return response.json()
            except Exception:
                return self._parse_html_response(response.text, domain, is_domain=True)

    def _parse_html_response(self, html: str, indicator: str, is_domain: bool = False) -> Dict[str, Any]:
        """Parse HTML response when JSON is not available."""
        # Basic parsing for reputation indicators
        result = {
            "ip" if not is_domain else "domain": indicator,
            "source": "talos_web",
        }

        html_lower = html.lower()

        # Check for reputation indicators in HTML
        if "poor" in html_lower:
            result["reputation"] = "Poor"
            result["reputation_score"] = -3
        elif "neutral" in html_lower:
            result["reputation"] = "Neutral"
            result["reputation_score"] = 0
        elif "good" in html_lower:
            result["reputation"] = "Good"
            result["reputation_score"] = 3
        else:
            result["reputation"] = "Unknown"
            result["reputation_score"] = 0

        # Check for threat categories
        threat_categories = []
        if "spam" in html_lower:
            threat_categories.append("Spam")
        if "malware" in html_lower:
            threat_categories.append("Malware")
        if "phishing" in html_lower:
            threat_categories.append("Phishing")
        if "botnet" in html_lower:
            threat_categories.append("Botnet")

        result["threat_categories"] = threat_categories

        return result

    def parse_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Talos lookup response into structured format."""
        if "error" in data:
            return data

        # Handle different response formats
        reputation = data.get("reputation", data.get("email_reputation", {}))

        if isinstance(reputation, dict):
            score = reputation.get("score", 0)
            status = reputation.get("status", "Unknown")
        else:
            score = data.get("reputation_score", 0)
            status = data.get("reputation", "Unknown")

        return {
            "ip": data.get("ip"),
            "domain": data.get("domain"),
            "reputation": status,
            "reputation_score": score,
            "threat_categories": data.get("threat_categories", []),
            "blacklists": data.get("blacklists", []),
            "blacklist_count": len(data.get("blacklists", [])),
            "volume": data.get("volume", {}),
            "email_reputation": data.get("email_reputation", {}),
            "web_reputation": data.get("web_reputation", {}),
            "source": data.get("source", "talos_api"),
        }

    def get_risk_assessment(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate risk assessment from parsed Talos data.

        Args:
            parsed_data: Parsed lookup response

        Returns:
            Risk assessment with level and reasons
        """
        if "error" in parsed_data:
            return {
                "risk_level": "info",
                "reasons": ["Not found in Talos database"],
                "recommendation": "No Talos reputation data available.",
            }

        reasons = []
        risk_level = "info"

        # Check reputation
        reputation = parsed_data.get("reputation", "").lower()
        score = parsed_data.get("reputation_score", 0)

        if reputation == "poor" or score < -2:
            risk_level = "high"
            reasons.append(f"Poor reputation in Talos (score: {score})")
        elif reputation == "neutral" or (-2 <= score <= 2):
            risk_level = "low"
            reasons.append(f"Neutral reputation in Talos (score: {score})")
        elif reputation == "good" or score > 2:
            risk_level = "info"
            reasons.append(f"Good reputation in Talos (score: {score})")
        else:
            reasons.append(f"Reputation: {reputation} (score: {score})")

        # Check threat categories
        categories = parsed_data.get("threat_categories", [])
        if categories:
            if any(c.lower() in ["malware", "botnet", "phishing"] for c in categories):
                risk_level = "critical"
            elif risk_level != "critical":
                risk_level = "high"
            reasons.append(f"Threat categories: {', '.join(categories)}")

        # Check blacklists
        blacklists = parsed_data.get("blacklists", [])
        if blacklists:
            if risk_level in ["info", "low"]:
                risk_level = "medium"
            reasons.append(f"Listed on {len(blacklists)} blacklist(s)")

        if not reasons:
            reasons.append("No significant Talos findings")

        return {
            "risk_level": risk_level,
            "reputation": parsed_data.get("reputation"),
            "reputation_score": score,
            "reasons": reasons,
            "recommendation": self._get_recommendation(risk_level, parsed_data),
        }

    def _get_recommendation(self, risk_level: str, parsed_data: Dict[str, Any]) -> str:
        """Get recommendation based on risk level and data."""
        categories = parsed_data.get("threat_categories", [])

        if "Malware" in categories:
            return "CRITICAL: Associated with malware distribution. Block immediately and investigate all connections."
        elif "Phishing" in categories:
            return "CRITICAL: Associated with phishing. Block and alert affected users."
        elif "Botnet" in categories:
            return "CRITICAL: Associated with botnet activity. May indicate compromised host."
        elif "Spam" in categories:
            return "HIGH RISK: Associated with spam. May be compromised or malicious."
        elif risk_level == "high":
            return "HIGH RISK: Poor Talos reputation. Investigate source and consider blocking."
        elif risk_level == "medium":
            return "MEDIUM RISK: Some negative indicators. Monitor traffic closely."
        elif risk_level == "low":
            return "LOW RISK: Neutral reputation. No immediate action required."
        else:
            return "Good reputation in Talos. No concerns."


# Tool definitions for Claude
TALOS_TOOLS = [
    {
        "name": "talos_lookup_ip",
        "description": "Look up an IP address in Cisco Talos Intelligence for reputation, threat categories, and blacklist status.",
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
        "name": "talos_lookup_domain",
        "description": "Look up a domain in Cisco Talos Intelligence for reputation and threat categories.",
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
]
