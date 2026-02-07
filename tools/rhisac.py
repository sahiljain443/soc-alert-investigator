"""RH-ISAC MISP API client for community threat intelligence."""

import httpx
from typing import Any, Dict, List, Optional


class RHISACClient:
    """
    Client for RH-ISAC MISP (Malware Information Sharing Platform) API.

    RH-ISAC provides:
    - Community-shared threat indicators
    - Vetted IOCs from retail/hospitality sector
    - MISP events and attributes
    - Threat tags and classifications
    """

    BASE_URL = "https://misp.rhisac.org"

    def __init__(self, api_key: str):
        """
        Initialize RH-ISAC MISP client.

        Args:
            api_key: RH-ISAC MISP API authentication key
        """
        self.api_key = api_key
        self.headers = {
            "Authorization": api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    async def search_indicator(
        self,
        value: str,
        indicator_type: Optional[str] = None,
        limit: int = 100,
        include_context: bool = True,
    ) -> Dict[str, Any]:
        """
        Search for an indicator in RH-ISAC MISP.

        Args:
            value: The IOC value to search for (IP, domain, hash, etc.)
            indicator_type: Optional MISP attribute type filter
            limit: Maximum number of results
            include_context: Whether to include event context

        Returns:
            MISP search results with matching attributes
        """
        search_params: Dict[str, Any] = {
            "value": value,
            "limit": limit,
            "includeContext": include_context,
            "includeCorrelations": True,
            "includeDecayScore": True,
        }

        if indicator_type:
            search_params["type"] = indicator_type

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.BASE_URL}/attributes/restSearch",
                headers=self.headers,
                json=search_params,
                timeout=30.0,
            )

            if response.status_code == 404:
                return {"error": "not_found", "value": value}

            if response.status_code == 403:
                return {"error": "unauthorized", "value": value}

            response.raise_for_status()
            return response.json()

    async def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """
        Look up an IP address in RH-ISAC MISP.

        Args:
            ip: IP address to look up

        Returns:
            MISP indicator data
        """
        # Search for both source and destination IP types
        result = await self.search_indicator(ip)
        result["queried_value"] = ip
        result["queried_type"] = "ip"
        return result

    async def lookup_domain(self, domain: str) -> Dict[str, Any]:
        """
        Look up a domain in RH-ISAC MISP.

        Args:
            domain: Domain to look up

        Returns:
            MISP indicator data
        """
        result = await self.search_indicator(domain)
        result["queried_value"] = domain
        result["queried_type"] = "domain"
        return result

    async def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Look up a file hash in RH-ISAC MISP.

        Args:
            file_hash: MD5, SHA1, or SHA256 hash

        Returns:
            MISP indicator data
        """
        result = await self.search_indicator(file_hash)
        result["queried_value"] = file_hash
        result["queried_type"] = "hash"
        return result

    async def lookup_url(self, url: str) -> Dict[str, Any]:
        """
        Look up a URL in RH-ISAC MISP.

        Args:
            url: URL to look up

        Returns:
            MISP indicator data
        """
        result = await self.search_indicator(url, indicator_type="url")
        result["queried_value"] = url
        result["queried_type"] = "url"
        return result

    async def get_recent_indicators(
        self,
        last: str = "1d",
        tags: Optional[List[str]] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """
        Get recent indicators from RH-ISAC MISP.

        Args:
            last: Time range (e.g., "1d", "7d", "30d")
            tags: Optional list of tags to filter by (e.g., ["rhisac: vetted"])
            limit: Maximum number of results

        Returns:
            Recent MISP attributes
        """
        search_params: Dict[str, Any] = {
            "last": last,
            "limit": limit,
        }

        if tags:
            search_params["tags"] = tags

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.BASE_URL}/attributes/restSearch",
                headers=self.headers,
                json=search_params,
                timeout=30.0,
            )
            response.raise_for_status()
            return response.json()

    def parse_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse MISP response into structured format.

        Args:
            data: Raw MISP API response

        Returns:
            Parsed and structured data
        """
        if "error" in data:
            return data

        response = data.get("response", {})
        attributes = response.get("Attribute", [])

        if not attributes:
            return {
                "error": "not_found",
                "value": data.get("queried_value", "unknown"),
            }

        # Extract unique events and tags
        events = {}
        all_tags = []
        threat_levels = []

        for attr in attributes:
            # Get event info if available
            event = attr.get("Event", {})
            event_id = event.get("id")
            if event_id and event_id not in events:
                events[event_id] = {
                    "id": event_id,
                    "info": event.get("info", ""),
                    "threat_level_id": event.get("threat_level_id"),
                    "date": event.get("date"),
                    "org": event.get("Orgc", {}).get("name", "Unknown"),
                }
                if event.get("threat_level_id"):
                    threat_levels.append(int(event.get("threat_level_id")))

            # Collect tags
            for tag in attr.get("Tag", []):
                tag_name = tag.get("name", "")
                if tag_name and tag_name not in all_tags:
                    all_tags.append(tag_name)

        # MISP threat levels: 1=High, 2=Medium, 3=Low, 4=Undefined
        min_threat_level = min(threat_levels) if threat_levels else 4

        return {
            "value": data.get("queried_value"),
            "type": data.get("queried_type"),
            "attribute_count": len(attributes),
            "event_count": len(events),
            "events": list(events.values())[:10],
            "tags": all_tags[:20],
            "threat_level": min_threat_level,
            "threat_level_name": self._threat_level_name(min_threat_level),
        }

    def _threat_level_name(self, level: int) -> str:
        """Convert MISP threat level ID to name."""
        levels = {
            1: "High",
            2: "Medium",
            3: "Low",
            4: "Undefined",
        }
        return levels.get(level, "Unknown")

    def get_risk_assessment(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate risk assessment from parsed RH-ISAC data.

        Args:
            parsed_data: Parsed lookup response

        Returns:
            Risk assessment with level and reasons
        """
        if "error" in parsed_data:
            return {
                "risk_level": "info",
                "reasons": ["Not found in RH-ISAC MISP database"],
                "recommendation": "No RH-ISAC community threat intelligence available.",
            }

        reasons = []
        risk_level = "info"

        attribute_count = parsed_data.get("attribute_count", 0)
        event_count = parsed_data.get("event_count", 0)
        threat_level = parsed_data.get("threat_level", 4)
        tags = parsed_data.get("tags", [])

        # Check MISP threat level
        if threat_level == 1:
            risk_level = "critical"
            reasons.append("CRITICAL: High threat level in RH-ISAC")
        elif threat_level == 2:
            risk_level = "high"
            reasons.append("HIGH: Medium threat level in RH-ISAC")
        elif threat_level == 3:
            risk_level = "medium"
            reasons.append("Low threat level in RH-ISAC")

        # Check event count
        if event_count > 10:
            if risk_level in ["info"]:
                risk_level = "high"
            reasons.append(f"Referenced in {event_count} threat events")
        elif event_count > 3:
            if risk_level in ["info"]:
                risk_level = "medium"
            reasons.append(f"Referenced in {event_count} threat events")
        elif event_count > 0:
            if risk_level == "info":
                risk_level = "low"
            reasons.append(f"Referenced in {event_count} threat event(s)")

        # Check for significant tags
        critical_tags = ["apt", "ransomware", "c2", "botnet", "targeted-attack"]
        high_tags = ["malware", "phishing", "credential-theft", "rhisac: vetted"]
        medium_tags = ["suspicious", "spam", "scanning"]

        found_critical = [t for t in tags if any(ct in t.lower() for ct in critical_tags)]
        found_high = [t for t in tags if any(ht in t.lower() for ht in high_tags)]
        found_medium = [t for t in tags if any(mt in t.lower() for mt in medium_tags)]

        if found_critical:
            if risk_level not in ["critical"]:
                risk_level = "critical"
            reasons.append(f"Critical tags: {', '.join(found_critical[:3])}")
        elif found_high:
            if risk_level in ["info", "low"]:
                risk_level = "high"
            reasons.append(f"High-risk tags: {', '.join(found_high[:3])}")
        elif found_medium:
            if risk_level in ["info"]:
                risk_level = "medium"
            reasons.append(f"Tags: {', '.join(found_medium[:3])}")

        # Add event info
        events = parsed_data.get("events", [])
        if events:
            event_names = [e.get("info", "")[:50] for e in events[:3] if e.get("info")]
            if event_names:
                reasons.append(f"Events: {', '.join(event_names)}")

        if not reasons:
            reasons.append("No significant RH-ISAC findings")

        return {
            "risk_level": risk_level,
            "event_count": event_count,
            "attribute_count": attribute_count,
            "threat_level": parsed_data.get("threat_level_name", "Unknown"),
            "reasons": reasons,
            "recommendation": self._get_recommendation(risk_level, parsed_data),
        }

    def _get_recommendation(self, risk_level: str, parsed_data: Dict[str, Any]) -> str:
        """Get recommendation based on risk level and data."""
        event_count = parsed_data.get("event_count", 0)

        if risk_level == "critical":
            return f"CRITICAL: Known threat indicator shared by RH-ISAC community ({event_count} events). Block immediately and investigate all connections."
        elif risk_level == "high":
            return f"HIGH RISK: Threat indicator reported by retail/hospitality sector. Review associated events and consider blocking."
        elif risk_level == "medium":
            return "MEDIUM RISK: Some threat associations in RH-ISAC. Investigate traffic patterns and context."
        elif risk_level == "low":
            return "LOW RISK: Minor associations in RH-ISAC. Monitor but likely low priority."
        else:
            return "No significant threat intelligence from RH-ISAC community."


# Tool definitions for Claude
RHISAC_TOOLS = [
    {
        "name": "rhisac_lookup_ip",
        "description": "Look up an IP address in RH-ISAC MISP for community-shared threat intelligence from the retail and hospitality sector.",
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
        "name": "rhisac_lookup_domain",
        "description": "Look up a domain in RH-ISAC MISP for community-shared threat intelligence.",
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
        "name": "rhisac_lookup_hash",
        "description": "Look up a file hash (MD5/SHA1/SHA256) in RH-ISAC MISP for malware associations.",
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
    {
        "name": "rhisac_lookup_url",
        "description": "Look up a URL in RH-ISAC MISP for phishing or malicious URL intelligence.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "The URL to look up",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "rhisac_get_recent",
        "description": "Get recent threat indicators from RH-ISAC MISP community.",
        "input_schema": {
            "type": "object",
            "properties": {
                "last": {
                    "type": "string",
                    "description": "Time range (e.g., '1d', '7d', '30d')",
                    "default": "1d",
                },
                "tags": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional tags to filter by (e.g., ['rhisac: vetted'])",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of results",
                    "default": 100,
                },
            },
        },
    },
]
