"""VirusTotal API client for threat intelligence."""

import httpx
from typing import Any, Dict, Optional

from models.ioc import IOC, IOCType
from models.finding import Finding


class VirusTotalClient:
    """Client for VirusTotal API v3."""

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str):
        """
        Initialize VirusTotal client.

        Args:
            api_key: VirusTotal API key
        """
        self.api_key = api_key
        self.headers = {"x-apikey": api_key}

    async def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """
        Look up an IP address in VirusTotal.

        Args:
            ip: IP address to look up

        Returns:
            VirusTotal response data
        """
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.BASE_URL}/ip_addresses/{ip}",
                headers=self.headers,
                timeout=30.0,
            )
            response.raise_for_status()
            return response.json()

    async def lookup_domain(self, domain: str) -> Dict[str, Any]:
        """
        Look up a domain in VirusTotal.

        Args:
            domain: Domain to look up

        Returns:
            VirusTotal response data
        """
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.BASE_URL}/domains/{domain}",
                headers=self.headers,
                timeout=30.0,
            )
            response.raise_for_status()
            return response.json()

    async def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Look up a file hash in VirusTotal.

        Args:
            file_hash: File hash (MD5, SHA1, or SHA256)

        Returns:
            VirusTotal response data
        """
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.BASE_URL}/files/{file_hash}",
                headers=self.headers,
                timeout=30.0,
            )
            response.raise_for_status()
            return response.json()

    async def lookup_url(self, url: str) -> Dict[str, Any]:
        """
        Look up a URL in VirusTotal.

        Args:
            url: URL to look up

        Returns:
            VirusTotal response data
        """
        import base64

        # URL needs to be base64 encoded for the API
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.BASE_URL}/urls/{url_id}",
                headers=self.headers,
                timeout=30.0,
            )
            response.raise_for_status()
            return response.json()

    async def lookup_ioc(self, ioc: IOC) -> Optional[Dict[str, Any]]:
        """
        Look up an IOC in VirusTotal based on its type.

        Args:
            ioc: IOC to look up

        Returns:
            VirusTotal response data or None if type not supported
        """
        try:
            if ioc.type == IOCType.IP_ADDRESS:
                return await self.lookup_ip(ioc.value)
            elif ioc.type == IOCType.DOMAIN:
                return await self.lookup_domain(ioc.value)
            elif ioc.type == IOCType.URL:
                return await self.lookup_url(ioc.value)
            elif ioc.is_hash:
                return await self.lookup_hash(ioc.value)
            else:
                return None
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return {"error": "not_found", "ioc": ioc.value}
            raise

    def parse_ip_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse IP lookup response into structured format."""
        if "error" in data:
            return data

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        return {
            "ip": data.get("data", {}).get("id"),
            "country": attrs.get("country"),
            "as_owner": attrs.get("as_owner"),
            "reputation": attrs.get("reputation", 0),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "total_votes": {
                "harmless": attrs.get("total_votes", {}).get("harmless", 0),
                "malicious": attrs.get("total_votes", {}).get("malicious", 0),
            },
        }

    def parse_domain_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse domain lookup response into structured format."""
        if "error" in data:
            return data

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        return {
            "domain": data.get("data", {}).get("id"),
            "registrar": attrs.get("registrar"),
            "creation_date": attrs.get("creation_date"),
            "reputation": attrs.get("reputation", 0),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "categories": attrs.get("categories", {}),
        }

    def parse_hash_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse file hash lookup response into structured format."""
        if "error" in data:
            return data

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        return {
            "sha256": attrs.get("sha256"),
            "sha1": attrs.get("sha1"),
            "md5": attrs.get("md5"),
            "file_type": attrs.get("type_description"),
            "file_size": attrs.get("size"),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "popular_threat_name": attrs.get("popular_threat_classification", {}).get(
                "suggested_threat_label"
            ),
            "tags": attrs.get("tags", []),
        }


# Tool definitions for Claude
VIRUSTOTAL_TOOLS = [
    {
        "name": "virustotal_lookup_ip",
        "description": "Look up an IP address in VirusTotal to check its reputation and see how many security vendors flag it as malicious.",
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
        "name": "virustotal_lookup_domain",
        "description": "Look up a domain in VirusTotal to check its reputation and security vendor verdicts.",
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
        "name": "virustotal_lookup_hash",
        "description": "Look up a file hash (MD5, SHA1, or SHA256) in VirusTotal to check if the file is known to be malicious.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_hash": {
                    "type": "string",
                    "description": "The file hash to look up (MD5, SHA1, or SHA256)",
                },
            },
            "required": ["file_hash"],
        },
    },
]
