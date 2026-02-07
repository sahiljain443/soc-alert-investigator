"""Investigation finding model."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    """Risk levels for findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingSource(str, Enum):
    """Source of the finding."""

    SPLUNK = "splunk"
    VIRUSTOTAL = "virustotal"
    ABUSEIPDB = "abuseipdb"
    IPINFO = "ipinfo"
    SPUR = "spur"
    SHODAN = "shodan"
    TALOS = "talos"
    OTX = "otx"
    RHISAC = "rhisac"
    IOC_EXTRACTION = "ioc_extraction"
    ANALYSIS = "analysis"
    THREAT_INTEL = "threat_intel"
    DEVICE_FINGERPRINT = "device_fingerprint"


class Finding(BaseModel):
    """Model representing an investigation finding."""

    source: FindingSource = Field(description="Source of the finding")
    title: str = Field(description="Finding title")
    description: str = Field(description="Detailed description")
    risk_level: RiskLevel = Field(default=RiskLevel.INFO, description="Risk level")
    ioc_value: Optional[str] = Field(default=None, description="Related IOC value if applicable")
    raw_data: Dict[str, Any] = Field(default_factory=dict, description="Raw data from source")
    timestamp: datetime = Field(default_factory=datetime.now, description="When finding was created")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0, description="Confidence score 0-1")

    @classmethod
    def from_splunk_result(cls, query: str, result: Dict[str, Any], ioc_value: Optional[str] = None) -> "Finding":
        """Create a finding from Splunk query results."""
        event_count = result.get("count", len(result.get("data", [])))

        if event_count == 0:
            return cls(
                source=FindingSource.SPLUNK,
                title="No matching events found",
                description=f"Query: {query}\nNo events matched the search criteria.",
                risk_level=RiskLevel.INFO,
                ioc_value=ioc_value,
                raw_data=result,
            )

        return cls(
            source=FindingSource.SPLUNK,
            title=f"Found {event_count} related events",
            description=f"Query: {query}\nDiscovered {event_count} events related to the investigation.",
            risk_level=RiskLevel.MEDIUM if event_count > 10 else RiskLevel.LOW,
            ioc_value=ioc_value,
            raw_data=result,
            confidence=min(0.9, 0.5 + (event_count * 0.05)),
        )

    @classmethod
    def from_virustotal(cls, ioc_value: str, vt_data: Dict[str, Any]) -> "Finding":
        """Create a finding from VirusTotal results."""
        stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0

        if malicious > 5:
            risk = RiskLevel.CRITICAL
            confidence = 0.95
        elif malicious > 0 or suspicious > 5:
            risk = RiskLevel.HIGH
            confidence = 0.85
        elif suspicious > 0:
            risk = RiskLevel.MEDIUM
            confidence = 0.7
        else:
            risk = RiskLevel.LOW
            confidence = 0.6

        return cls(
            source=FindingSource.VIRUSTOTAL,
            title=f"VirusTotal: {malicious}/{total} engines flagged as malicious",
            description=f"IOC: {ioc_value}\nMalicious: {malicious}, Suspicious: {suspicious}, Total engines: {total}",
            risk_level=risk,
            ioc_value=ioc_value,
            raw_data=vt_data,
            confidence=confidence,
        )

    @classmethod
    def from_abuseipdb(cls, ip: str, abuse_data: Dict[str, Any]) -> "Finding":
        """Create a finding from AbuseIPDB results."""
        data = abuse_data.get("data", {})
        abuse_score = data.get("abuseConfidenceScore", 0)
        total_reports = data.get("totalReports", 0)
        country = data.get("countryCode", "Unknown")
        isp = data.get("isp", "Unknown")

        if abuse_score >= 80:
            risk = RiskLevel.CRITICAL
            confidence = 0.95
        elif abuse_score >= 50:
            risk = RiskLevel.HIGH
            confidence = 0.85
        elif abuse_score >= 25:
            risk = RiskLevel.MEDIUM
            confidence = 0.7
        elif total_reports > 0:
            risk = RiskLevel.LOW
            confidence = 0.6
        else:
            risk = RiskLevel.INFO
            confidence = 0.5

        return cls(
            source=FindingSource.ABUSEIPDB,
            title=f"AbuseIPDB: Abuse confidence score {abuse_score}%",
            description=f"IP: {ip}\nAbuse Score: {abuse_score}%\nTotal Reports: {total_reports}\nCountry: {country}\nISP: {isp}",
            risk_level=risk,
            ioc_value=ip,
            raw_data=abuse_data,
            confidence=confidence,
        )

    @classmethod
    def from_ipinfo(cls, ip: str, ipinfo_data: Dict[str, Any]) -> "Finding":
        """Create a finding from IPInfo results."""
        privacy = ipinfo_data.get("privacy", {})
        is_vpn = privacy.get("vpn", False)
        is_proxy = privacy.get("proxy", False)
        is_tor = privacy.get("tor", False)
        is_relay = privacy.get("relay", False)
        is_hosting = privacy.get("hosting", False)

        country = ipinfo_data.get("country", "Unknown")
        city = ipinfo_data.get("city", "")
        org = ipinfo_data.get("org", "Unknown")
        hostname = ipinfo_data.get("hostname", "")

        # Determine risk based on privacy indicators
        if is_tor:
            risk = RiskLevel.HIGH
            confidence = 0.9
            indicator = "Tor Exit Node"
        elif is_proxy:
            risk = RiskLevel.MEDIUM
            confidence = 0.8
            indicator = "Known Proxy"
        elif is_hosting:
            risk = RiskLevel.MEDIUM
            confidence = 0.7
            indicator = "Hosting/Datacenter"
        elif is_vpn:
            risk = RiskLevel.LOW
            confidence = 0.7
            indicator = "VPN Service"
        elif is_relay:
            risk = RiskLevel.LOW
            confidence = 0.6
            indicator = "iCloud Private Relay"
        else:
            risk = RiskLevel.INFO
            confidence = 0.5
            indicator = "Standard IP"

        location = f"{city}, {country}" if city else country
        description_parts = [
            f"IP: {ip}",
            f"Location: {location}",
            f"Organization: {org}",
        ]
        if hostname:
            description_parts.append(f"Hostname: {hostname}")
        if is_vpn or is_proxy or is_tor or is_relay or is_hosting:
            privacy_flags = []
            if is_tor:
                privacy_flags.append("Tor")
            if is_proxy:
                privacy_flags.append("Proxy")
            if is_vpn:
                privacy_flags.append("VPN")
            if is_relay:
                privacy_flags.append("Relay")
            if is_hosting:
                privacy_flags.append("Hosting")
            description_parts.append(f"Privacy Flags: {', '.join(privacy_flags)}")

        return cls(
            source=FindingSource.IPINFO,
            title=f"IPInfo: {indicator} - {location}",
            description="\n".join(description_parts),
            risk_level=risk,
            ioc_value=ip,
            raw_data=ipinfo_data,
            confidence=confidence,
        )

    @classmethod
    def from_spur(cls, ip: str, spur_data: Dict[str, Any]) -> "Finding":
        """Create a finding from Spur.us results."""
        tunnels = spur_data.get("tunnels", [])
        client_info = spur_data.get("client", {})
        as_info = spur_data.get("as", {})

        # Determine anonymity type
        is_residential_proxy = False
        is_vpn = False
        is_proxy = False
        is_tor = False
        anonymity_types = []

        for tunnel in tunnels:
            tunnel_type = tunnel.get("type", "").lower()
            operator = tunnel.get("operator", "Unknown")

            if "residential" in tunnel_type and "proxy" in tunnel_type:
                is_residential_proxy = True
                anonymity_types.append(f"Residential Proxy ({operator})")
            elif "vpn" in tunnel_type:
                is_vpn = True
                anonymity_types.append(f"VPN ({operator})")
            elif "proxy" in tunnel_type:
                is_proxy = True
                anonymity_types.append(f"Proxy ({operator})")
            elif "tor" in tunnel_type:
                is_tor = True
                anonymity_types.append("Tor Exit Node")

        # Risk assessment
        if is_residential_proxy:
            risk = RiskLevel.HIGH
            confidence = 0.9
            indicator = "Residential Proxy"
        elif is_tor:
            risk = RiskLevel.HIGH
            confidence = 0.9
            indicator = "Tor Exit Node"
        elif is_proxy:
            risk = RiskLevel.MEDIUM
            confidence = 0.8
            indicator = "Proxy"
        elif is_vpn:
            risk = RiskLevel.LOW
            confidence = 0.7
            indicator = "VPN"
        else:
            risk = RiskLevel.INFO
            confidence = 0.5
            indicator = "No Anonymity Detected"

        description_parts = [f"IP: {ip}"]
        if as_info:
            description_parts.append(f"AS: {as_info.get('organization', 'Unknown')} ({as_info.get('number', '')})")

        if anonymity_types:
            description_parts.append(f"Anonymity: {', '.join(anonymity_types)}")
        else:
            description_parts.append("Anonymity: None detected")

        client_behaviors = client_info.get("behaviors", [])
        if client_behaviors:
            description_parts.append(f"Behaviors: {', '.join(client_behaviors[:3])}")

        return cls(
            source=FindingSource.SPUR,
            title=f"Spur: {indicator}",
            description="\n".join(description_parts),
            risk_level=risk,
            ioc_value=ip,
            raw_data=spur_data,
            confidence=confidence,
        )

    @classmethod
    def from_shodan(cls, ip: str, shodan_data: Dict[str, Any]) -> "Finding":
        """Create a finding from Shodan results."""
        if "error" in shodan_data:
            return cls(
                source=FindingSource.SHODAN,
                title="Shodan: Not found",
                description=f"IP {ip} not found in Shodan database",
                risk_level=RiskLevel.INFO,
                ioc_value=ip,
                raw_data=shodan_data,
                confidence=0.5,
            )

        ports = shodan_data.get("ports", [])
        vulns = []
        for item in shodan_data.get("data", []):
            vulns.extend(item.get("vulns", {}).keys())
        vulns = list(set(vulns))

        org = shodan_data.get("org", "Unknown")
        isp = shodan_data.get("isp", "Unknown")
        tags = shodan_data.get("tags", [])

        # Risk assessment based on vulnerabilities and tags
        if len(vulns) > 10:
            risk = RiskLevel.CRITICAL
            confidence = 0.9
        elif len(vulns) > 5:
            risk = RiskLevel.HIGH
            confidence = 0.85
        elif len(vulns) > 0:
            risk = RiskLevel.MEDIUM
            confidence = 0.75
        elif any(t in ["vpn", "proxy", "tor"] for t in tags):
            risk = RiskLevel.MEDIUM
            confidence = 0.7
        else:
            risk = RiskLevel.INFO
            confidence = 0.5

        description_parts = [
            f"IP: {ip}",
            f"Organization: {org}",
            f"ISP: {isp}",
            f"Open Ports: {len(ports)} ({', '.join(map(str, ports[:10]))}{'...' if len(ports) > 10 else ''})",
        ]

        if vulns:
            description_parts.append(f"Vulnerabilities: {len(vulns)} ({', '.join(vulns[:5])}{'...' if len(vulns) > 5 else ''})")

        if tags:
            description_parts.append(f"Tags: {', '.join(tags)}")

        return cls(
            source=FindingSource.SHODAN,
            title=f"Shodan: {len(ports)} ports, {len(vulns)} vulns",
            description="\n".join(description_parts),
            risk_level=risk,
            ioc_value=ip,
            raw_data=shodan_data,
            confidence=confidence,
        )

    @classmethod
    def from_talos(cls, indicator: str, talos_data: Dict[str, Any]) -> "Finding":
        """Create a finding from Cisco Talos results."""
        if "error" in talos_data:
            return cls(
                source=FindingSource.TALOS,
                title="Talos: Not found",
                description=f"Indicator {indicator} not found in Talos database",
                risk_level=RiskLevel.INFO,
                ioc_value=indicator,
                raw_data=talos_data,
                confidence=0.5,
            )

        reputation = talos_data.get("reputation", "Unknown")
        score = talos_data.get("reputation_score", 0)
        categories = talos_data.get("threat_categories", [])
        blacklists = talos_data.get("blacklists", [])

        # Risk assessment
        if "Malware" in categories or "Botnet" in categories:
            risk = RiskLevel.CRITICAL
            confidence = 0.95
        elif "Phishing" in categories or "Spam" in categories:
            risk = RiskLevel.HIGH
            confidence = 0.9
        elif blacklists:
            risk = RiskLevel.HIGH
            confidence = 0.85
        elif reputation.lower() == "poor" or score < -2:
            risk = RiskLevel.HIGH
            confidence = 0.8
        elif reputation.lower() == "neutral":
            risk = RiskLevel.LOW
            confidence = 0.6
        else:
            risk = RiskLevel.INFO
            confidence = 0.5

        description_parts = [
            f"Indicator: {indicator}",
            f"Reputation: {reputation} (score: {score})",
        ]

        if categories:
            description_parts.append(f"Threat Categories: {', '.join(categories)}")

        if blacklists:
            description_parts.append(f"Blacklists: {len(blacklists)}")

        return cls(
            source=FindingSource.TALOS,
            title=f"Talos: {reputation} reputation",
            description="\n".join(description_parts),
            risk_level=risk,
            ioc_value=indicator,
            raw_data=talos_data,
            confidence=confidence,
        )

    @classmethod
    def from_otx(cls, indicator: str, otx_data: Dict[str, Any]) -> "Finding":
        """Create a finding from AlienVault OTX results."""
        if "error" in otx_data:
            return cls(
                source=FindingSource.OTX,
                title="OTX: Not found",
                description=f"Indicator {indicator} not found in OTX database",
                risk_level=RiskLevel.INFO,
                ioc_value=indicator,
                raw_data=otx_data,
                confidence=0.5,
            )

        pulse_info = otx_data.get("pulse_info", {})
        pulse_count = pulse_info.get("count", 0)
        pulses = pulse_info.get("pulses", [])
        malware_data = otx_data.get("malware", {})
        malware_count = len(malware_data.get("data", []))

        # Extract tags from pulses
        all_tags = []
        for pulse in pulses[:10]:
            all_tags.extend(pulse.get("tags", []))
        unique_tags = list(set(all_tags))[:10]

        # Risk assessment based on pulse count and malware associations
        if pulse_count > 50 or malware_count > 10:
            risk = RiskLevel.CRITICAL
            confidence = 0.95
        elif pulse_count > 20 or malware_count > 5:
            risk = RiskLevel.HIGH
            confidence = 0.85
        elif pulse_count > 5 or malware_count > 0:
            risk = RiskLevel.MEDIUM
            confidence = 0.7
        elif pulse_count > 0:
            risk = RiskLevel.LOW
            confidence = 0.6
        else:
            risk = RiskLevel.INFO
            confidence = 0.5

        description_parts = [
            f"Indicator: {indicator}",
            f"Threat Pulses: {pulse_count}",
        ]

        if malware_count > 0:
            description_parts.append(f"Malware Samples: {malware_count}")

        if unique_tags:
            description_parts.append(f"Tags: {', '.join(unique_tags)}")

        pulse_names = [p.get("name", "") for p in pulses[:3] if p.get("name")]
        if pulse_names:
            description_parts.append(f"Top Pulses: {', '.join(pulse_names)}")

        return cls(
            source=FindingSource.OTX,
            title=f"OTX: {pulse_count} pulses, {malware_count} malware samples",
            description="\n".join(description_parts),
            risk_level=risk,
            ioc_value=indicator,
            raw_data=otx_data,
            confidence=confidence,
        )

    @classmethod
    def from_rhisac(cls, indicator: str, rhisac_data: Dict[str, Any]) -> "Finding":
        """Create a finding from RH-ISAC MISP results."""
        if "error" in rhisac_data:
            return cls(
                source=FindingSource.RHISAC,
                title="RH-ISAC: Not found",
                description=f"Indicator {indicator} not found in RH-ISAC MISP database",
                risk_level=RiskLevel.INFO,
                ioc_value=indicator,
                raw_data=rhisac_data,
                confidence=0.5,
            )

        # Parse MISP response
        response = rhisac_data.get("response", {})
        attributes = response.get("Attribute", [])

        if not attributes:
            return cls(
                source=FindingSource.RHISAC,
                title="RH-ISAC: Not found",
                description=f"Indicator {indicator} not found in RH-ISAC MISP database",
                risk_level=RiskLevel.INFO,
                ioc_value=indicator,
                raw_data=rhisac_data,
                confidence=0.5,
            )

        # Extract event info and tags
        events = {}
        all_tags = []
        threat_levels = []

        for attr in attributes:
            event = attr.get("Event", {})
            event_id = event.get("id")
            if event_id and event_id not in events:
                events[event_id] = {
                    "info": event.get("info", ""),
                    "threat_level_id": event.get("threat_level_id"),
                    "org": event.get("Orgc", {}).get("name", "Unknown"),
                }
                if event.get("threat_level_id"):
                    threat_levels.append(int(event.get("threat_level_id")))

            for tag in attr.get("Tag", []):
                tag_name = tag.get("name", "")
                if tag_name and tag_name not in all_tags:
                    all_tags.append(tag_name)

        attribute_count = len(attributes)
        event_count = len(events)

        # MISP threat levels: 1=High, 2=Medium, 3=Low, 4=Undefined
        min_threat_level = min(threat_levels) if threat_levels else 4
        threat_level_names = {1: "High", 2: "Medium", 3: "Low", 4: "Undefined"}
        threat_level_name = threat_level_names.get(min_threat_level, "Unknown")

        # Determine risk level based on MISP threat level and event count
        if min_threat_level == 1 or event_count > 10:
            risk = RiskLevel.CRITICAL
            confidence = 0.95
        elif min_threat_level == 2 or event_count > 5:
            risk = RiskLevel.HIGH
            confidence = 0.85
        elif min_threat_level == 3 or event_count > 2:
            risk = RiskLevel.MEDIUM
            confidence = 0.7
        elif event_count > 0:
            risk = RiskLevel.LOW
            confidence = 0.6
        else:
            risk = RiskLevel.INFO
            confidence = 0.5

        # Check for critical tags
        critical_tags = ["apt", "ransomware", "c2", "botnet", "rhisac: vetted"]
        found_critical = [t for t in all_tags if any(ct in t.lower() for ct in critical_tags)]
        if found_critical and risk not in [RiskLevel.CRITICAL]:
            risk = RiskLevel.HIGH
            confidence = max(confidence, 0.85)

        description_parts = [
            f"Indicator: {indicator}",
            f"Events: {event_count}",
            f"Attributes: {attribute_count}",
            f"Threat Level: {threat_level_name}",
        ]

        if all_tags:
            description_parts.append(f"Tags: {', '.join(all_tags[:5])}{'...' if len(all_tags) > 5 else ''}")

        event_list = list(events.values())
        if event_list:
            event_names = [e.get("info", "")[:40] for e in event_list[:3] if e.get("info")]
            if event_names:
                description_parts.append(f"Top Events: {', '.join(event_names)}")

        return cls(
            source=FindingSource.RHISAC,
            title=f"RH-ISAC: {event_count} events, {threat_level_name} threat level",
            description="\n".join(description_parts),
            risk_level=risk,
            ioc_value=indicator,
            raw_data=rhisac_data,
            confidence=confidence,
        )
