"""Threat Intelligence Enricher - Tier 2: Enriches IOCs with threat intel."""

import asyncio
from typing import Any, Dict, List, Optional, Tuple

from config import Config
from models.ioc import IOC, IOCType
from models.finding import Finding, FindingSource, RiskLevel
from tools.virustotal import VirusTotalClient
from tools.abuseipdb import AbuseIPDBClient
from tools.ipinfo import IPInfoClient
from tools.spur import SpurClient
from tools.shodan_client import ShodanClient
from tools.talos import TalosClient
from tools.otx import OTXClient
from tools.rhisac import RHISACClient
from utils.console_output import ConsoleOutput


class ThreatIntelEnricher:
    """
    Tier 2 Threat Intelligence Enricher.

    Enriches IOCs using VirusTotal and AbuseIPDB APIs.
    """

    def __init__(self, config: Optional[Config] = None, console: Optional[ConsoleOutput] = None):
        """Initialize the Threat Intel Enricher."""
        self.config = config or Config.from_env()
        self.console = console or ConsoleOutput()

        # Initialize API clients if keys are available
        self.vt_client = VirusTotalClient(self.config.virustotal_api_key) if self.config.virustotal_api_key else None
        self.abuse_client = AbuseIPDBClient(self.config.abuseipdb_api_key) if self.config.abuseipdb_api_key else None
        self.ipinfo_client = IPInfoClient(self.config.ipinfo_api_key) if self.config.ipinfo_api_key else None
        self.spur_client = SpurClient(self.config.spur_api_key) if self.config.spur_api_key else None
        self.shodan_client = ShodanClient(self.config.shodan_api_key) if self.config.shodan_api_key else None
        self.talos_client = TalosClient(self.config.talos_api_key) if self.config.talos_api_key else None
        self.otx_client = OTXClient(self.config.otx_api_key) if self.config.otx_api_key else None
        self.rhisac_client = RHISACClient(self.config.rhisac_api_key) if self.config.rhisac_api_key else None

    def get_enrichable_iocs(self, iocs: List[IOC]) -> List[IOC]:
        """
        Filter IOCs that can be enriched via threat intel.

        Args:
            iocs: List of all IOCs

        Returns:
            List of IOCs suitable for threat intel lookup
        """
        enrichable = []

        for ioc in iocs:
            # Skip internal IPs
            if ioc.type == IOCType.IP_ADDRESS and ioc.is_internal:
                continue

            # Only enrich certain types
            if ioc.type in (
                IOCType.IP_ADDRESS,
                IOCType.DOMAIN,
                IOCType.URL,
                IOCType.FILE_HASH_MD5,
                IOCType.FILE_HASH_SHA1,
                IOCType.FILE_HASH_SHA256,
            ):
                enrichable.append(ioc)

        return enrichable

    async def enrich_iocs(self, iocs: List[IOC]) -> List[Finding]:
        """
        Enrich IOCs with threat intelligence.

        Args:
            iocs: List of IOCs to enrich

        Returns:
            List of findings from threat intel lookups
        """
        findings: List[Finding] = []
        enrichable = self.get_enrichable_iocs(iocs)

        if not enrichable:
            return findings

        # Run enrichment for each IOC
        tasks = []
        for ioc in enrichable:
            if ioc.type == IOCType.IP_ADDRESS:
                tasks.append(self._enrich_ip(ioc))
            elif ioc.type == IOCType.DOMAIN:
                tasks.append(self._enrich_domain(ioc))
            elif ioc.is_hash:
                tasks.append(self._enrich_hash(ioc))
            elif ioc.type == IOCType.URL:
                tasks.append(self._enrich_url(ioc))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                continue
            elif isinstance(result, list):
                findings.extend(result)
            elif isinstance(result, Finding):
                findings.append(result)

        return findings

    # ------------------------------------------------------------------
    # Per-source coroutines (IP)
    # ------------------------------------------------------------------

    async def _lookup_vt_ip(self, ip: str) -> Finding:
        try:
            vt_data = await self.vt_client.lookup_ip(ip)
            return Finding.from_virustotal(ip, vt_data)
        except Exception as e:
            return Finding(source=FindingSource.VIRUSTOTAL, title=f"VirusTotal lookup failed for {ip}",
                           description=str(e), risk_level=RiskLevel.INFO, ioc_value=ip)

    async def _lookup_abuse_ip(self, ip: str) -> Finding:
        try:
            abuse_data = await self.abuse_client.check_ip(ip)
            return Finding.from_abuseipdb(ip, abuse_data)
        except Exception as e:
            return Finding(source=FindingSource.ABUSEIPDB, title=f"AbuseIPDB lookup failed for {ip}",
                           description=str(e), risk_level=RiskLevel.INFO, ioc_value=ip)

    async def _lookup_ipinfo_ip(self, ip: str) -> Finding:
        try:
            ipinfo_data = await self.ipinfo_client.lookup_ip(ip)
            return Finding.from_ipinfo(ip, ipinfo_data)
        except Exception as e:
            return Finding(source=FindingSource.IPINFO, title=f"IPInfo lookup failed for {ip}",
                           description=str(e), risk_level=RiskLevel.INFO, ioc_value=ip)

    async def _lookup_spur_ip(self, ip: str) -> Finding:
        try:
            spur_data = await self.spur_client.lookup_ip(ip)
            return Finding.from_spur(ip, spur_data)
        except Exception as e:
            return Finding(source=FindingSource.SPUR, title=f"Spur lookup failed for {ip}",
                           description=str(e), risk_level=RiskLevel.INFO, ioc_value=ip)

    async def _lookup_shodan_ip(self, ip: str) -> Finding:
        try:
            shodan_data = await self.shodan_client.lookup_ip(ip)
            return Finding.from_shodan(ip, shodan_data)
        except Exception as e:
            return Finding(source=FindingSource.SHODAN, title=f"Shodan lookup failed for {ip}",
                           description=str(e), risk_level=RiskLevel.INFO, ioc_value=ip)

    async def _lookup_talos_ip(self, ip: str) -> Finding:
        try:
            talos_data = await self.talos_client.lookup_ip(ip)
            return Finding.from_talos(ip, talos_data)
        except Exception as e:
            return Finding(source=FindingSource.TALOS, title=f"Talos lookup failed for {ip}",
                           description=str(e), risk_level=RiskLevel.INFO, ioc_value=ip)

    async def _lookup_otx_ip(self, ip: str) -> Finding:
        try:
            otx_data = await self.otx_client.lookup_ip(ip)
            return Finding.from_otx(ip, otx_data)
        except Exception as e:
            return Finding(source=FindingSource.OTX, title=f"OTX lookup failed for {ip}",
                           description=str(e), risk_level=RiskLevel.INFO, ioc_value=ip)

    async def _lookup_rhisac_ip(self, ip: str) -> Finding:
        try:
            rhisac_data = await self.rhisac_client.lookup_ip(ip)
            return Finding.from_rhisac(ip, rhisac_data)
        except Exception as e:
            return Finding(source=FindingSource.RHISAC, title=f"RH-ISAC lookup failed for {ip}",
                           description=str(e), risk_level=RiskLevel.INFO, ioc_value=ip)

    # ------------------------------------------------------------------
    # Per-source coroutines (Domain)
    # ------------------------------------------------------------------

    async def _lookup_vt_domain(self, domain: str) -> Finding:
        try:
            vt_data = await self.vt_client.lookup_domain(domain)
            return self._create_domain_finding(domain, vt_data)
        except Exception as e:
            return Finding(source=FindingSource.VIRUSTOTAL, title=f"VirusTotal lookup failed for {domain}",
                           description=str(e), risk_level=RiskLevel.INFO, ioc_value=domain)

    async def _lookup_shodan_domain(self, domain: str) -> Finding:
        try:
            shodan_data = await self.shodan_client.lookup_domain(domain)
            return self._create_shodan_domain_finding(domain, shodan_data)
        except Exception as e:
            return Finding(source=FindingSource.SHODAN, title=f"Shodan lookup failed for {domain}",
                           description=str(e), risk_level=RiskLevel.INFO, ioc_value=domain)

    async def _lookup_talos_domain(self, domain: str) -> Finding:
        try:
            talos_data = await self.talos_client.lookup_domain(domain)
            return Finding.from_talos(domain, talos_data)
        except Exception as e:
            return Finding(source=FindingSource.TALOS, title=f"Talos lookup failed for {domain}",
                           description=str(e), risk_level=RiskLevel.INFO, ioc_value=domain)

    async def _lookup_otx_domain(self, domain: str) -> Finding:
        try:
            otx_data = await self.otx_client.lookup_domain(domain)
            return Finding.from_otx(domain, otx_data)
        except Exception as e:
            return Finding(source=FindingSource.OTX, title=f"OTX lookup failed for {domain}",
                           description=str(e), risk_level=RiskLevel.INFO, ioc_value=domain)

    async def _lookup_rhisac_domain(self, domain: str) -> Finding:
        try:
            rhisac_data = await self.rhisac_client.lookup_domain(domain)
            return Finding.from_rhisac(domain, rhisac_data)
        except Exception as e:
            return Finding(source=FindingSource.RHISAC, title=f"RH-ISAC lookup failed for {domain}",
                           description=str(e), risk_level=RiskLevel.INFO, ioc_value=domain)

    # ------------------------------------------------------------------
    # Per-source coroutines (Hash)
    # ------------------------------------------------------------------

    async def _lookup_vt_hash(self, file_hash: str) -> Finding:
        try:
            vt_data = await self.vt_client.lookup_hash(file_hash)
            return self._create_hash_finding(file_hash, vt_data)
        except Exception as e:
            return Finding(source=FindingSource.VIRUSTOTAL, title="VirusTotal lookup failed for hash",
                           description=str(e), risk_level=RiskLevel.INFO, ioc_value=file_hash)

    async def _lookup_otx_hash(self, file_hash: str) -> Finding:
        try:
            otx_data = await self.otx_client.lookup_hash(file_hash)
            return Finding.from_otx(file_hash, otx_data)
        except Exception as e:
            return Finding(source=FindingSource.OTX, title="OTX lookup failed for hash",
                           description=str(e), risk_level=RiskLevel.INFO, ioc_value=file_hash)

    async def _lookup_rhisac_hash(self, file_hash: str) -> Finding:
        try:
            rhisac_data = await self.rhisac_client.lookup_hash(file_hash)
            return Finding.from_rhisac(file_hash, rhisac_data)
        except Exception as e:
            return Finding(source=FindingSource.RHISAC, title="RH-ISAC lookup failed for hash",
                           description=str(e), risk_level=RiskLevel.INFO, ioc_value=file_hash)

    # ------------------------------------------------------------------
    # Per-source coroutines (URL)
    # ------------------------------------------------------------------

    async def _lookup_vt_url(self, url: str) -> Finding:
        try:
            vt_data = await self.vt_client.lookup_url(url)
            return self._create_url_finding(url, vt_data)
        except Exception as e:
            return Finding(source=FindingSource.VIRUSTOTAL, title="VirusTotal lookup failed for URL",
                           description=str(e), risk_level=RiskLevel.INFO, ioc_value=url)

    async def _lookup_otx_url(self, url: str) -> Finding:
        try:
            otx_data = await self.otx_client.lookup_url(url)
            return Finding.from_otx(url, otx_data)
        except Exception as e:
            return Finding(source=FindingSource.OTX, title="OTX lookup failed for URL",
                           description=str(e), risk_level=RiskLevel.INFO, ioc_value=url)

    async def _lookup_rhisac_url(self, url: str) -> Finding:
        try:
            rhisac_data = await self.rhisac_client.lookup_url(url)
            return Finding.from_rhisac(url, rhisac_data)
        except Exception as e:
            return Finding(source=FindingSource.RHISAC, title="RH-ISAC lookup failed for URL",
                           description=str(e), risk_level=RiskLevel.INFO, ioc_value=url)

    # ------------------------------------------------------------------
    # Enrichment entry points (parallelised per-source via gather)
    # ------------------------------------------------------------------

    async def _enrich_ip(self, ioc: IOC) -> List[Finding]:
        """Enrich an IP address with threat intel (all sources in parallel)."""
        ip = ioc.value
        tasks = []

        if self.vt_client:
            tasks.append(self._lookup_vt_ip(ip))
        if self.abuse_client:
            tasks.append(self._lookup_abuse_ip(ip))
        if self.ipinfo_client:
            tasks.append(self._lookup_ipinfo_ip(ip))
        if self.spur_client:
            tasks.append(self._lookup_spur_ip(ip))
        if self.shodan_client:
            tasks.append(self._lookup_shodan_ip(ip))
        if self.talos_client:
            tasks.append(self._lookup_talos_ip(ip))
        if self.otx_client:
            tasks.append(self._lookup_otx_ip(ip))
        if self.rhisac_client:
            tasks.append(self._lookup_rhisac_ip(ip))

        if not tasks:
            return [Finding(
                source=FindingSource.ANALYSIS,
                title=f"No threat intel available for IP: {ip}",
                description="Threat intel API keys not configured.",
                risk_level=RiskLevel.INFO,
                ioc_value=ip,
            )]

        return list(await asyncio.gather(*tasks))


    async def _enrich_domain(self, ioc: IOC) -> List[Finding]:
        """Enrich a domain with threat intel (all sources in parallel)."""
        domain = ioc.value
        tasks = []

        if self.vt_client:
            tasks.append(self._lookup_vt_domain(domain))
        if self.shodan_client:
            tasks.append(self._lookup_shodan_domain(domain))
        if self.talos_client:
            tasks.append(self._lookup_talos_domain(domain))
        if self.otx_client:
            tasks.append(self._lookup_otx_domain(domain))
        if self.rhisac_client:
            tasks.append(self._lookup_rhisac_domain(domain))

        if not tasks:
            return [Finding(
                source=FindingSource.ANALYSIS,
                title=f"No threat intel available for domain: {domain}",
                description="Threat intel API keys not configured.",
                risk_level=RiskLevel.INFO,
                ioc_value=domain,
            )]

        return list(await asyncio.gather(*tasks))

    async def _enrich_hash(self, ioc: IOC) -> List[Finding]:
        """Enrich a file hash with threat intel (all sources in parallel)."""
        file_hash = ioc.value
        tasks = []

        if self.vt_client:
            tasks.append(self._lookup_vt_hash(file_hash))
        if self.otx_client:
            tasks.append(self._lookup_otx_hash(file_hash))
        if self.rhisac_client:
            tasks.append(self._lookup_rhisac_hash(file_hash))

        if not tasks:
            return [Finding(
                source=FindingSource.ANALYSIS,
                title="No threat intel available for hash",
                description="Threat intel API keys not configured.",
                risk_level=RiskLevel.INFO,
                ioc_value=file_hash,
            )]

        return list(await asyncio.gather(*tasks))

    async def _enrich_url(self, ioc: IOC) -> List[Finding]:
        """Enrich a URL with threat intel (all sources in parallel)."""
        url = ioc.value
        tasks = []

        if self.vt_client:
            tasks.append(self._lookup_vt_url(url))
        if self.otx_client:
            tasks.append(self._lookup_otx_url(url))
        if self.rhisac_client:
            tasks.append(self._lookup_rhisac_url(url))

        if not tasks:
            return [Finding(
                source=FindingSource.ANALYSIS,
                title="No threat intel available for URL",
                description="Threat intel API keys not configured.",
                risk_level=RiskLevel.INFO,
                ioc_value=url,
            )]

        return list(await asyncio.gather(*tasks))

    def _create_domain_finding(self, domain: str, vt_data: Dict[str, Any]) -> Finding:
        """Create a finding from VirusTotal domain lookup."""
        if "error" in vt_data:
            return Finding(
                source=FindingSource.VIRUSTOTAL,
                title=f"Domain not found: {domain}",
                description="Domain not in VirusTotal database.",
                risk_level=RiskLevel.INFO,
                ioc_value=domain,
                raw_data=vt_data,
            )

        attrs = vt_data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0

        if malicious > 5:
            risk = RiskLevel.CRITICAL
        elif malicious > 0 or suspicious > 5:
            risk = RiskLevel.HIGH
        elif suspicious > 0:
            risk = RiskLevel.MEDIUM
        else:
            risk = RiskLevel.LOW

        return Finding(
            source=FindingSource.VIRUSTOTAL,
            title=f"VirusTotal: Domain {domain} - {malicious}/{total} malicious",
            description=f"Domain: {domain}\nMalicious: {malicious}, Suspicious: {suspicious}",
            risk_level=risk,
            ioc_value=domain,
            raw_data=vt_data,
        )

    def _create_hash_finding(self, file_hash: str, vt_data: Dict[str, Any]) -> Finding:
        """Create a finding from VirusTotal hash lookup."""
        if "error" in vt_data:
            return Finding(
                source=FindingSource.VIRUSTOTAL,
                title=f"Hash not found in VirusTotal",
                description=f"Hash: {file_hash}\nFile not in VirusTotal database.",
                risk_level=RiskLevel.INFO,
                ioc_value=file_hash,
                raw_data=vt_data,
            )

        attrs = vt_data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0

        threat_label = attrs.get("popular_threat_classification", {}).get("suggested_threat_label", "Unknown")

        if malicious > 10:
            risk = RiskLevel.CRITICAL
        elif malicious > 3:
            risk = RiskLevel.HIGH
        elif malicious > 0 or suspicious > 3:
            risk = RiskLevel.MEDIUM
        else:
            risk = RiskLevel.LOW

        return Finding(
            source=FindingSource.VIRUSTOTAL,
            title=f"VirusTotal: {malicious}/{total} detections - {threat_label}",
            description=f"Hash: {file_hash}\nThreat: {threat_label}\nMalicious: {malicious}",
            risk_level=risk,
            ioc_value=file_hash,
            raw_data=vt_data,
        )

    def _create_url_finding(self, url: str, vt_data: Dict[str, Any]) -> Finding:
        """Create a finding from VirusTotal URL lookup."""
        if "error" in vt_data:
            return Finding(
                source=FindingSource.VIRUSTOTAL,
                title=f"URL not found in VirusTotal",
                description="URL not in VirusTotal database.",
                risk_level=RiskLevel.INFO,
                ioc_value=url,
                raw_data=vt_data,
            )

        attrs = vt_data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0

        if malicious > 5:
            risk = RiskLevel.CRITICAL
        elif malicious > 0 or suspicious > 5:
            risk = RiskLevel.HIGH
        elif suspicious > 0:
            risk = RiskLevel.MEDIUM
        else:
            risk = RiskLevel.LOW

        return Finding(
            source=FindingSource.VIRUSTOTAL,
            title=f"VirusTotal: URL - {malicious}/{total} malicious",
            description=f"Malicious: {malicious}, Suspicious: {suspicious}",
            risk_level=risk,
            ioc_value=url,
            raw_data=vt_data,
        )

    def _create_shodan_domain_finding(self, domain: str, shodan_data: Dict[str, Any]) -> Finding:
        """Create a finding from Shodan domain lookup."""
        if "error" in shodan_data:
            return Finding(
                source=FindingSource.SHODAN,
                title=f"Shodan: Domain not found",
                description=f"Domain {domain} not in Shodan database.",
                risk_level=RiskLevel.INFO,
                ioc_value=domain,
                raw_data=shodan_data,
            )

        subdomains = shodan_data.get("subdomains", [])
        records = shodan_data.get("data", [])
        tags = shodan_data.get("tags", [])

        description_parts = [
            f"Domain: {domain}",
            f"Subdomains: {len(subdomains)}",
            f"DNS Records: {len(records)}",
        ]

        if subdomains:
            description_parts.append(f"Sample subdomains: {', '.join(subdomains[:5])}{'...' if len(subdomains) > 5 else ''}")

        if tags:
            description_parts.append(f"Tags: {', '.join(tags)}")

        # Risk based on findings
        if any(t in ["malware", "c2", "phishing"] for t in tags):
            risk = RiskLevel.CRITICAL
        elif any(t in ["vpn", "proxy", "tor"] for t in tags):
            risk = RiskLevel.MEDIUM
        else:
            risk = RiskLevel.INFO

        return Finding(
            source=FindingSource.SHODAN,
            title=f"Shodan: {len(subdomains)} subdomains, {len(records)} records",
            description="\n".join(description_parts),
            risk_level=risk,
            ioc_value=domain,
            raw_data=shodan_data,
        )


# Convenience function for direct use
async def enrich_iocs(iocs: List[IOC], config: Optional[Config] = None) -> List[Finding]:
    """Enrich IOCs with threat intelligence."""
    enricher = ThreatIntelEnricher(config)
    return await enricher.enrich_iocs(iocs)
