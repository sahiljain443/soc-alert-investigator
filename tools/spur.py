"""Spur.us API client for VPN/Proxy/Anonymous infrastructure detection."""

import httpx
from typing import Any, Dict

from models.finding import Finding


class SpurClient:
    """
    Client for Spur.us API.

    Spur specializes in detecting:
    - Residential proxies
    - VPN services
    - Tor exit nodes
    - Datacenter proxies
    - Anonymous infrastructure
    """

    BASE_URL = "https://api.spur.us/v2"

    def __init__(self, api_key: str):
        """
        Initialize Spur client.

        Args:
            api_key: Spur API token
        """
        self.api_key = api_key
        self.headers = {
            "Token": api_key,
            "Accept": "application/json",
        }

    async def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """
        Look up an IP address in Spur for anonymity detection.

        Args:
            ip: IP address to look up

        Returns:
            Spur response data with anonymity context
        """
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.BASE_URL}/context/{ip}",
                headers=self.headers,
                timeout=30.0,
            )
            response.raise_for_status()
            return response.json()

    def parse_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Spur lookup response into structured format."""
        # Handle different response structures
        as_info = data.get("as", {})
        location = data.get("location", {})
        tunnels = data.get("tunnels", [])
        client_info = data.get("client", {})

        # Determine anonymity types
        anonymity_types = []
        is_vpn = False
        is_proxy = False
        is_residential_proxy = False
        is_datacenter = False
        is_tor = False

        # Check tunnels for VPN/proxy info
        for tunnel in tunnels:
            tunnel_type = tunnel.get("type", "").lower()
            operator = tunnel.get("operator", "")

            if "vpn" in tunnel_type:
                is_vpn = True
                anonymity_types.append(f"VPN ({operator})" if operator else "VPN")
            if "proxy" in tunnel_type:
                is_proxy = True
                if "residential" in tunnel_type:
                    is_residential_proxy = True
                    anonymity_types.append(f"Residential Proxy ({operator})" if operator else "Residential Proxy")
                else:
                    anonymity_types.append(f"Proxy ({operator})" if operator else "Proxy")
            if "tor" in tunnel_type:
                is_tor = True
                anonymity_types.append("Tor Exit Node")

        # Check client behaviors
        client_behaviors = client_info.get("behaviors", [])
        client_types = client_info.get("types", [])

        # Check for datacenter
        if as_info.get("type") == "hosting" or "DATACENTER" in client_types:
            is_datacenter = True
            if "Datacenter" not in anonymity_types:
                anonymity_types.append("Datacenter")

        return {
            "ip": data.get("ip"),
            "as_number": as_info.get("number"),
            "as_name": as_info.get("organization"),
            "as_type": as_info.get("type"),
            "country": location.get("country"),
            "city": location.get("city"),
            "state": location.get("state"),
            # Anonymity detection
            "is_vpn": is_vpn,
            "is_proxy": is_proxy,
            "is_residential_proxy": is_residential_proxy,
            "is_datacenter": is_datacenter,
            "is_tor": is_tor,
            "is_anonymous": is_vpn or is_proxy or is_tor,
            "anonymity_types": anonymity_types,
            # Tunnel details
            "tunnels": tunnels,
            "tunnel_count": len(tunnels),
            # Client info
            "client_behaviors": client_behaviors,
            "client_types": client_types,
            # Risk indicators
            "client_concentration": client_info.get("concentration"),
            "client_spread": client_info.get("spread"),
        }

    def get_risk_assessment(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate risk assessment from parsed Spur data.

        Args:
            parsed_data: Parsed lookup response

        Returns:
            Risk assessment with level and reasons
        """
        reasons = []
        risk_level = "info"

        # Check for residential proxy (highest risk for ATO)
        if parsed_data.get("is_residential_proxy"):
            risk_level = "high"
            reasons.append("Residential proxy detected - commonly used for account takeover")

        # Check for Tor
        elif parsed_data.get("is_tor"):
            risk_level = "high"
            reasons.append("Tor exit node detected - anonymization network")

        # Check for VPN
        elif parsed_data.get("is_vpn"):
            risk_level = "medium"
            reasons.append("VPN service detected")

        # Check for other proxy types
        elif parsed_data.get("is_proxy"):
            risk_level = "medium"
            reasons.append("Proxy service detected")

        # Check for datacenter
        elif parsed_data.get("is_datacenter"):
            risk_level = "low"
            reasons.append("Datacenter/hosting IP")

        # Add tunnel details
        tunnels = parsed_data.get("tunnels", [])
        if tunnels:
            for tunnel in tunnels[:3]:
                operator = tunnel.get("operator", "Unknown")
                tunnel_type = tunnel.get("type", "Unknown")
                reasons.append(f"Tunnel: {tunnel_type} via {operator}")

        # Add client behaviors if present
        behaviors = parsed_data.get("client_behaviors", [])
        if behaviors:
            reasons.append(f"Client behaviors: {', '.join(behaviors[:3])}")

        if not reasons:
            reasons.append("No anonymity indicators detected")

        return {
            "risk_level": risk_level,
            "is_anonymous": parsed_data.get("is_anonymous", False),
            "anonymity_types": parsed_data.get("anonymity_types", []),
            "reasons": reasons,
            "recommendation": self._get_recommendation(risk_level, parsed_data),
        }

    def _get_recommendation(self, risk_level: str, parsed_data: Dict[str, Any]) -> str:
        """Get recommendation based on risk level and data."""
        if parsed_data.get("is_residential_proxy"):
            return "HIGH RISK: Residential proxy detected. These are commonly used for account takeover attacks. Verify user identity and consider blocking."
        elif parsed_data.get("is_tor"):
            return "HIGH RISK: Tor exit node. Exercise extreme caution - commonly used for anonymization in malicious activities."
        elif parsed_data.get("is_vpn"):
            return "MEDIUM RISK: VPN detected. May be legitimate privacy tool or attempt to mask location. Verify if VPN usage is expected."
        elif parsed_data.get("is_proxy"):
            return "MEDIUM RISK: Proxy detected. Investigate why user is accessing through a proxy."
        elif parsed_data.get("is_datacenter"):
            return "LOW RISK: Datacenter IP. May indicate automated traffic or cloud-based access."
        else:
            return "No anonymity indicators. IP appears to be a standard residential or business connection."


# Tool definitions for Claude
SPUR_TOOLS = [
    {
        "name": "spur_lookup_ip",
        "description": "Look up an IP address in Spur.us to detect VPN, proxy, residential proxy, or Tor usage. Spur specializes in anonymous infrastructure detection.",
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
