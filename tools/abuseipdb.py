"""AbuseIPDB API client for IP reputation."""

import httpx
from typing import Any, Dict, List

from models.finding import Finding


class AbuseIPDBClient:
    """Client for AbuseIPDB API v2."""

    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: str):
        """
        Initialize AbuseIPDB client.

        Args:
            api_key: AbuseIPDB API key
        """
        self.api_key = api_key
        self.headers = {
            "Key": api_key,
            "Accept": "application/json",
        }

    async def check_ip(self, ip: str, max_age_days: int = 90) -> Dict[str, Any]:
        """
        Check an IP address against AbuseIPDB.

        Args:
            ip: IP address to check
            max_age_days: Maximum age of reports to consider (1-365)

        Returns:
            AbuseIPDB response data
        """
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.BASE_URL}/check",
                headers=self.headers,
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": max_age_days,
                    "verbose": True,
                },
                timeout=30.0,
            )
            response.raise_for_status()
            return response.json()

    async def get_reports(self, ip: str, max_age_days: int = 90, limit: int = 25) -> Dict[str, Any]:
        """
        Get detailed reports for an IP address.

        Args:
            ip: IP address to get reports for
            max_age_days: Maximum age of reports
            limit: Maximum number of reports to return

        Returns:
            AbuseIPDB reports response
        """
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.BASE_URL}/reports",
                headers=self.headers,
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": max_age_days,
                    "perPage": limit,
                },
                timeout=30.0,
            )
            response.raise_for_status()
            return response.json()

    def parse_check_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse IP check response into structured format."""
        info = data.get("data", {})

        return {
            "ip": info.get("ipAddress"),
            "is_public": info.get("isPublic", True),
            "ip_version": info.get("ipVersion"),
            "is_whitelisted": info.get("isWhitelisted", False),
            "abuse_confidence_score": info.get("abuseConfidenceScore", 0),
            "country_code": info.get("countryCode"),
            "country_name": info.get("countryName"),
            "usage_type": info.get("usageType"),
            "isp": info.get("isp"),
            "domain": info.get("domain"),
            "hostnames": info.get("hostnames", []),
            "total_reports": info.get("totalReports", 0),
            "num_distinct_users": info.get("numDistinctUsers", 0),
            "last_reported_at": info.get("lastReportedAt"),
        }

    def get_risk_assessment(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate risk assessment from parsed AbuseIPDB data.

        Args:
            parsed_data: Parsed check response

        Returns:
            Risk assessment with level and reasons
        """
        score = parsed_data.get("abuse_confidence_score", 0)
        total_reports = parsed_data.get("total_reports", 0)
        distinct_users = parsed_data.get("num_distinct_users", 0)

        reasons = []
        risk_level = "low"

        if score >= 80:
            risk_level = "critical"
            reasons.append(f"Very high abuse confidence score ({score}%)")
        elif score >= 50:
            risk_level = "high"
            reasons.append(f"High abuse confidence score ({score}%)")
        elif score >= 25:
            risk_level = "medium"
            reasons.append(f"Moderate abuse confidence score ({score}%)")
        elif score > 0:
            risk_level = "low"
            reasons.append(f"Low abuse confidence score ({score}%)")
        else:
            risk_level = "info"
            reasons.append("No abuse reports found")

        if total_reports > 100:
            reasons.append(f"High number of reports ({total_reports})")
        elif total_reports > 10:
            reasons.append(f"Multiple reports ({total_reports})")

        if distinct_users > 10:
            reasons.append(f"Reported by {distinct_users} distinct users")

        if parsed_data.get("is_whitelisted"):
            risk_level = "info"
            reasons = ["IP is whitelisted"]

        return {
            "risk_level": risk_level,
            "abuse_score": score,
            "reasons": reasons,
            "recommendation": self._get_recommendation(risk_level, score),
        }

    def _get_recommendation(self, risk_level: str, score: int) -> str:
        """Get recommendation based on risk level."""
        if risk_level == "critical":
            return "Immediate action recommended. Consider blocking this IP and investigating all related activity."
        elif risk_level == "high":
            return "High priority investigation needed. Review all connections from/to this IP."
        elif risk_level == "medium":
            return "Monitor this IP closely and investigate any suspicious activity."
        elif risk_level == "low":
            return "Low risk but maintain awareness. Include in routine monitoring."
        else:
            return "No immediate action required. IP appears clean."


# Tool definitions for Claude
ABUSEIPDB_TOOLS = [
    {
        "name": "abuseipdb_check_ip",
        "description": "Check an IP address against AbuseIPDB to get its abuse confidence score and report history.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip": {
                    "type": "string",
                    "description": "The IP address to check",
                },
                "max_age_days": {
                    "type": "integer",
                    "description": "Maximum age of reports to consider (1-365). Defaults to 90.",
                    "default": 90,
                },
            },
            "required": ["ip"],
        },
    },
    {
        "name": "abuseipdb_get_reports",
        "description": "Get detailed abuse reports for an IP address from AbuseIPDB.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip": {
                    "type": "string",
                    "description": "The IP address to get reports for",
                },
                "max_age_days": {
                    "type": "integer",
                    "description": "Maximum age of reports (1-365). Defaults to 90.",
                    "default": 90,
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of reports to return. Defaults to 25.",
                    "default": 25,
                },
            },
            "required": ["ip"],
        },
    },
]
