"""Configuration management for SOC Alert Investigator."""

import os
from dataclasses import dataclass
from typing import List

# Try to load dotenv if available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


@dataclass
class Config:
    """Application configuration loaded from environment variables."""

    virustotal_api_key: str
    abuseipdb_api_key: str
    ipinfo_api_key: str
    spur_api_key: str
    shodan_api_key: str
    talos_api_key: str
    otx_api_key: str
    rhisac_api_key: str
    # DataDog configuration
    dd_api_key: str
    dd_app_key: str
    dd_site: str

    @classmethod
    def from_env(cls) -> "Config":
        """Load configuration from environment variables."""
        return cls(
            virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY", ""),
            abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY", ""),
            ipinfo_api_key=os.getenv("IPINFO_API_KEY", ""),
            spur_api_key=os.getenv("SPUR_API_KEY", ""),
            shodan_api_key=os.getenv("SHODAN_API_KEY", ""),
            talos_api_key=os.getenv("TALOS_API_KEY", ""),
            otx_api_key=os.getenv("OTX_API_KEY", ""),
            rhisac_api_key=os.getenv("RHISAC_API_KEY", ""),
            dd_api_key=os.getenv("DD_API_KEY", ""),
            dd_app_key=os.getenv("DD_APP_KEY", ""),
            dd_site=os.getenv("DD_SITE", "datadoghq.com"),
        )

    def validate(self) -> List[str]:
        """Validate configuration and return list of warnings."""
        warnings = []
        if not self.virustotal_api_key:
            warnings.append("VIRUSTOTAL_API_KEY not set - VirusTotal lookups will be skipped")
        if not self.abuseipdb_api_key:
            warnings.append("ABUSEIPDB_API_KEY not set - AbuseIPDB lookups will be skipped")
        if not self.ipinfo_api_key:
            warnings.append("IPINFO_API_KEY not set - IPInfo lookups will be skipped")
        if not self.spur_api_key:
            warnings.append("SPUR_API_KEY not set - Spur lookups will be skipped")
        if not self.shodan_api_key:
            warnings.append("SHODAN_API_KEY not set - Shodan lookups will be skipped")
        if not self.talos_api_key:
            warnings.append("TALOS_API_KEY not set - Talos lookups will be skipped")
        if not self.otx_api_key:
            warnings.append("OTX_API_KEY not set - AlienVault OTX lookups will be skipped")
        if not self.rhisac_api_key:
            warnings.append("RHISAC_API_KEY not set - RH-ISAC MISP lookups will be skipped")
        return warnings
