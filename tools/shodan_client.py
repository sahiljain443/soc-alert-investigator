"""Shodan API client for internet-wide scanning data."""

import httpx
from typing import Any, Dict, List, Optional

from models.finding import Finding


class ShodanClient:
    """
    Client for Shodan API.

    Shodan provides:
    - Open ports and services
    - Vulnerabilities (CVEs)
    - SSL/TLS certificate info
    - Hosting provider details
    - Historical scan data
    """

    BASE_URL = "https://api.shodan.io"

    def __init__(self, api_key: str):
        """
        Initialize Shodan client.

        Args:
            api_key: Shodan API key
        """
        self.api_key = api_key

    async def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """
        Look up an IP address in Shodan.

        Args:
            ip: IP address to look up

        Returns:
            Shodan host information
        """
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.BASE_URL}/shodan/host/{ip}",
                params={"key": self.api_key},
                timeout=30.0,
            )
            if response.status_code == 404:
                return {"error": "not_found", "ip": ip}
            response.raise_for_status()
            return response.json()

    async def lookup_domain(self, domain: str) -> Dict[str, Any]:
        """
        Look up a domain in Shodan DNS.

        Args:
            domain: Domain to look up

        Returns:
            Shodan DNS information
        """
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.BASE_URL}/dns/domain/{domain}",
                params={"key": self.api_key},
                timeout=30.0,
            )
            if response.status_code == 404:
                return {"error": "not_found", "domain": domain}
            response.raise_for_status()
            return response.json()

    def parse_ip_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse IP lookup response into structured format."""
        if "error" in data:
            return data

        # Extract open ports
        ports = data.get("ports", [])

        # Extract services/products
        services = []
        vulns = set()
        for item in data.get("data", []):
            service_info = {
                "port": item.get("port"),
                "transport": item.get("transport"),
                "product": item.get("product"),
                "version": item.get("version"),
                "module": item.get("_shodan", {}).get("module"),
            }
            services.append(service_info)

            # Collect vulnerabilities
            item_vulns = item.get("vulns", {})
            vulns.update(item_vulns.keys())

        # Extract hostnames
        hostnames = data.get("hostnames", [])

        # Extract tags
        tags = data.get("tags", [])

        return {
            "ip": data.get("ip_str"),
            "hostnames": hostnames,
            "country": data.get("country_name"),
            "country_code": data.get("country_code"),
            "city": data.get("city"),
            "org": data.get("org"),
            "isp": data.get("isp"),
            "asn": data.get("asn"),
            # Port and service info
            "ports": ports,
            "port_count": len(ports),
            "services": services,
            # Vulnerabilities
            "vulnerabilities": list(vulns),
            "vuln_count": len(vulns),
            # Tags (e.g., "vpn", "proxy", "tor")
            "tags": tags,
            # Timestamps
            "last_update": data.get("last_update"),
        }

    def parse_domain_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse domain lookup response into structured format."""
        if "error" in data:
            return data

        return {
            "domain": data.get("domain"),
            "subdomains": data.get("subdomains", []),
            "subdomain_count": len(data.get("subdomains", [])),
            "records": data.get("data", []),
            "tags": data.get("tags", []),
        }

    def get_risk_assessment(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate risk assessment from parsed Shodan data.

        Args:
            parsed_data: Parsed lookup response

        Returns:
            Risk assessment with level and reasons
        """
        if "error" in parsed_data:
            return {
                "risk_level": "info",
                "reasons": ["IP not found in Shodan database"],
                "recommendation": "No scan data available. IP may be behind NAT or not publicly exposed.",
            }

        reasons = []
        risk_level = "info"

        # Check for vulnerabilities
        vulns = parsed_data.get("vulnerabilities", [])
        if vulns:
            if len(vulns) > 10:
                risk_level = "critical"
                reasons.append(f"CRITICAL: {len(vulns)} known vulnerabilities detected")
            elif len(vulns) > 5:
                risk_level = "high"
                reasons.append(f"HIGH: {len(vulns)} known vulnerabilities detected")
            else:
                risk_level = "medium"
                reasons.append(f"{len(vulns)} known vulnerabilities: {', '.join(vulns[:5])}")

        # Check for suspicious tags
        tags = parsed_data.get("tags", [])
        suspicious_tags = ["vpn", "proxy", "tor", "compromised", "malware", "c2"]
        found_suspicious = [t for t in tags if any(s in t.lower() for s in suspicious_tags)]
        if found_suspicious:
            if risk_level == "info":
                risk_level = "medium"
            reasons.append(f"Suspicious tags: {', '.join(found_suspicious)}")

        # Check for risky open ports
        ports = parsed_data.get("ports", [])
        risky_ports = {
            22: "SSH",
            23: "Telnet",
            3389: "RDP",
            5900: "VNC",
            445: "SMB",
            1433: "MSSQL",
            3306: "MySQL",
            27017: "MongoDB",
        }
        exposed_risky = [(p, risky_ports[p]) for p in ports if p in risky_ports]
        if exposed_risky:
            if risk_level == "info":
                risk_level = "low"
            port_list = ", ".join(f"{p} ({name})" for p, name in exposed_risky[:5])
            reasons.append(f"Exposed services: {port_list}")

        # Add general port info
        if ports:
            reasons.append(f"Open ports: {len(ports)} ({', '.join(map(str, ports[:10]))}{'...' if len(ports) > 10 else ''})")

        # Add organization info
        org = parsed_data.get("org")
        isp = parsed_data.get("isp")
        if org:
            reasons.append(f"Organization: {org}")
        if isp and isp != org:
            reasons.append(f"ISP: {isp}")

        if not reasons:
            reasons.append("No significant findings in Shodan data")

        return {
            "risk_level": risk_level,
            "vuln_count": len(vulns),
            "port_count": len(ports),
            "reasons": reasons,
            "recommendation": self._get_recommendation(risk_level, parsed_data),
        }

    def _get_recommendation(self, risk_level: str, parsed_data: Dict[str, Any]) -> str:
        """Get recommendation based on risk level and data."""
        vulns = parsed_data.get("vulnerabilities", [])

        if risk_level == "critical":
            return f"CRITICAL: Multiple vulnerabilities detected. This IP may be compromised or used for attacks. Investigate all traffic from this IP immediately."
        elif risk_level == "high":
            return f"HIGH RISK: {len(vulns)} vulnerabilities found. Review exposed services and investigate connection purpose."
        elif risk_level == "medium":
            return "MEDIUM RISK: Some concerning indicators found. Include in investigation scope."
        elif risk_level == "low":
            return "LOW RISK: Exposed services detected but no critical issues. Monitor traffic patterns."
        else:
            return "No significant risk indicators from Shodan scan data."


# Tool definitions for Claude
SHODAN_TOOLS = [
    {
        "name": "shodan_lookup_ip",
        "description": "Look up an IP address in Shodan to find open ports, services, vulnerabilities, and hosting information.",
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
        "name": "shodan_lookup_domain",
        "description": "Look up a domain in Shodan to find subdomains and DNS records.",
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
