"""IPInfo API client for IP geolocation and enrichment."""

import httpx
from typing import Any, Dict

from models.finding import Finding


class IPInfoClient:
    """Client for IPInfo API."""

    BASE_URL = "https://ipinfo.io"

    def __init__(self, api_key: str):
        """
        Initialize IPInfo client.

        Args:
            api_key: IPInfo API key
        """
        self.api_key = api_key

    async def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """
        Look up an IP address in IPInfo.

        Args:
            ip: IP address to look up

        Returns:
            IPInfo response data
        """
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.BASE_URL}/{ip}",
                params={"token": self.api_key},
                timeout=30.0,
            )
            response.raise_for_status()
            return response.json()

    async def lookup_ip_full(self, ip: str) -> Dict[str, Any]:
        """
        Get full IP details including privacy and company data.

        Args:
            ip: IP address to look up

        Returns:
            Full IPInfo response with privacy detection
        """
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.BASE_URL}/{ip}",
                params={"token": self.api_key},
                timeout=30.0,
            )
            response.raise_for_status()
            return response.json()

    def parse_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse IP lookup response into structured format."""
        privacy = data.get("privacy", {})
        company = data.get("company", {})
        asn = data.get("asn", {})

        return {
            "ip": data.get("ip"),
            "hostname": data.get("hostname"),
            "city": data.get("city"),
            "region": data.get("region"),
            "country": data.get("country"),
            "country_name": data.get("country_name"),
            "location": data.get("loc"),
            "organization": data.get("org"),
            "postal": data.get("postal"),
            "timezone": data.get("timezone"),
            # Privacy detection (requires paid plan)
            "is_vpn": privacy.get("vpn", False),
            "is_proxy": privacy.get("proxy", False),
            "is_tor": privacy.get("tor", False),
            "is_relay": privacy.get("relay", False),
            "is_hosting": privacy.get("hosting", False),
            # Company info (if available)
            "company_name": company.get("name"),
            "company_domain": company.get("domain"),
            "company_type": company.get("type"),
            # ASN info (if available)
            "asn": asn.get("asn"),
            "asn_name": asn.get("name"),
            "asn_domain": asn.get("domain"),
            "asn_type": asn.get("type"),
        }

    def get_risk_assessment(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate risk assessment from parsed IPInfo data.

        Args:
            parsed_data: Parsed lookup response

        Returns:
            Risk assessment with level and reasons
        """
        reasons = []
        risk_level = "info"

        # Check privacy flags (VPN, Proxy, Tor, Hosting)
        is_vpn = parsed_data.get("is_vpn", False)
        is_proxy = parsed_data.get("is_proxy", False)
        is_tor = parsed_data.get("is_tor", False)
        is_relay = parsed_data.get("is_relay", False)
        is_hosting = parsed_data.get("is_hosting", False)

        if is_tor:
            risk_level = "high"
            reasons.append("IP is a Tor exit node")
        elif is_proxy:
            risk_level = "medium"
            reasons.append("IP is a known proxy")
        elif is_vpn:
            risk_level = "low"
            reasons.append("IP is associated with a VPN service")
        elif is_relay:
            risk_level = "low"
            reasons.append("IP is an iCloud Private Relay")
        elif is_hosting:
            risk_level = "medium"
            reasons.append("IP belongs to a hosting/datacenter provider")

        # Check ASN type
        asn_type = parsed_data.get("asn_type", "")
        if asn_type == "hosting":
            if risk_level == "info":
                risk_level = "low"
            reasons.append(f"ASN type: hosting/datacenter")
        elif asn_type == "business":
            reasons.append(f"ASN type: business")
        elif asn_type == "isp":
            reasons.append(f"ASN type: ISP (residential)")

        # Add geographic context
        country = parsed_data.get("country_name") or parsed_data.get("country")
        city = parsed_data.get("city")
        if country:
            reasons.append(f"Location: {city}, {country}" if city else f"Country: {country}")

        # Add organization info
        org = parsed_data.get("organization")
        if org:
            reasons.append(f"Organization: {org}")

        if not reasons:
            reasons.append("Standard IP with no notable indicators")

        return {
            "risk_level": risk_level,
            "reasons": reasons,
            "is_anonymous": is_vpn or is_proxy or is_tor or is_relay,
            "is_datacenter": is_hosting or asn_type == "hosting",
            "recommendation": self._get_recommendation(risk_level, parsed_data),
        }

    def _get_recommendation(self, risk_level: str, parsed_data: Dict[str, Any]) -> str:
        """Get recommendation based on risk level and data."""
        is_tor = parsed_data.get("is_tor", False)
        is_proxy = parsed_data.get("is_proxy", False)
        is_hosting = parsed_data.get("is_hosting", False)

        if is_tor:
            return "Tor exit node detected. Exercise caution - commonly used for anonymization in both legitimate and malicious activities."
        elif is_proxy:
            return "Known proxy IP. Verify if proxy usage is expected for this user/service."
        elif is_hosting:
            return "Datacenter/hosting IP. May indicate automated traffic or cloud-based attacks."
        elif risk_level == "low":
            return "Minor indicators present. Include in broader investigation context."
        else:
            return "No significant risk indicators. Geographic and ownership data available for context."


# Tool definitions for Claude
IPINFO_TOOLS = [
    {
        "name": "ipinfo_lookup_ip",
        "description": "Look up an IP address in IPInfo to get geolocation, organization, and privacy detection (VPN/Proxy/Tor).",
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
]
