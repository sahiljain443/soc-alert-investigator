# SOC Alert Investigator

A multi-tier Python application for automated security alert investigation, designed to run within Claude Code sessions using MCP (Model Context Protocol) for Splunk integration and threat intelligence APIs.

## Features

- **Automated IOC Extraction** - Extracts IP addresses, domains, URLs, file hashes (MD5/SHA1/SHA256), emails, usernames, and CVEs from alert data
- **Splunk Query Generation** - Generates targeted SPL queries for investigating extracted IOCs
- **Threat Intelligence Enrichment** - Concurrent lookups against VirusTotal and AbuseIPDB
- **Device Fingerprint Analysis** - JA3/JA4 TLS fingerprint analysis for account takeover detection
- **Risk Assessment** - Multi-factor risk scoring with confidence levels
- **Investigation Reports** - Comprehensive reports with actionable recommendations

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Claude Code Session                     │
│                    (Orchestrating LLM Brain)                 │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  Tier 1: Orchestrator                                        │
│  - Parse alerts, extract IOCs, coordinate workflow           │
└─────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┴───────────────┐
              ▼                               ▼
┌─────────────────────────┐     ┌─────────────────────────┐
│  Tier 2: Splunk         │     │  Tier 2: Threat Intel   │
│  Investigator           │     │  Enricher               │
│  - Generate SPL queries │     │  - VirusTotal lookups   │
│  - Analyze results      │     │  - AbuseIPDB lookups    │
│  - Detect patterns      │     │  - Concurrent execution │
└─────────────────────────┘     └─────────────────────────┘
              │                               │
              └───────────────┬───────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  Tier 3: Reporter                                            │
│  - Consolidate findings, calculate risk, generate report     │
└─────────────────────────────────────────────────────────────┘
```

## Prerequisites

- Python 3.9+
- Claude Code CLI with active session
- Splunk MCP server configured
- API keys for threat intelligence (optional but recommended)

## Installation

```bash
# Navigate to the project
cd soc-alert-investigator

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Configuration

Create a `.env` file in the project root:

```env
VIRUSTOTAL_API_KEY=your_virustotal_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
IPINFO_API_KEY=your_ipinfo_api_key
SPUR_API_KEY=your_spur_api_key
SHODAN_API_KEY=your_shodan_api_key
TALOS_API_KEY=your_talos_api_key
OTX_API_KEY=your_otx_api_key
```

### Obtaining API Keys

- **VirusTotal**: Sign up at [virustotal.com](https://www.virustotal.com/) and get your API key from the API section
- **AbuseIPDB**: Register at [abuseipdb.com](https://www.abuseipdb.com/) and generate an API key
- **IPInfo**: Sign up at [ipinfo.io](https://ipinfo.io/) and get your API token from the dashboard
- **Spur**: Sign up at [spur.us](https://spur.us/) and get your API key from the context API section
- **Shodan**: Register at [shodan.io](https://www.shodan.io/) and get your API key from account settings
- **Talos**: Access [talosintelligence.com](https://talosintelligence.com/) - basic lookups work without a key
- **OTX**: Sign up at [otx.alienvault.com](https://otx.alienvault.com/) and get your API key from Settings

The application will function without API keys but threat intelligence enrichment will be skipped for unconfigured sources.

## Usage

### CLI Modes

```bash
# Use sample alert for testing
python main.py --sample

# Load alert from JSON file
python main.py --file path/to/alert.json

# Interactive mode (paste JSON, then Ctrl+D)
python main.py

# Output plan as JSON for programmatic use
python main.py --sample --json
```

### Within Claude Code Session

The primary use case is running investigations from within a Claude Code session:

1. **Generate Investigation Plan**
   ```bash
   python main.py --file alert.json
   ```

2. **Execute with Claude** - Ask Claude to:
   - Execute the generated Splunk queries via MCP
   - Run threat intel enrichment on external IOCs
   - Generate the final investigation report

### Programmatic API

```python
from investigate import (
    parse_and_plan,
    run_threat_intel_enrichment,
    generate_investigation_report
)

# Step 1: Parse alert and generate investigation plan
plan = parse_and_plan(alert_json)

# Step 2: Claude executes Splunk queries via MCP
# mcp__splunk__run_splunk_query(query=plan['splunk_queries'][0]['query'])

# Step 3: Enrich IOCs with threat intelligence
import asyncio
findings = asyncio.run(run_threat_intel_enrichment(plan['enrichable_iocs']))

# Step 4: Generate report
report = generate_investigation_report(
    alert=plan['alert'],
    iocs=plan['iocs'],
    findings=findings
)
```

## Project Structure

```
soc-alert-investigator/
├── agents/
│   ├── orchestrator.py         # Tier 1: Workflow coordination
│   ├── splunk_investigator.py  # Tier 2: Splunk query generation
│   ├── threat_intel.py         # Tier 2: Threat intel enrichment
│   └── reporter.py             # Tier 3: Report generation
├── models/
│   ├── alert.py                # DataDogAlert model
│   ├── ioc.py                  # IOC and IOCType models
│   └── finding.py              # Finding and RiskLevel models
├── tools/
│   ├── splunk_tools.py         # Splunk MCP interface
│   ├── virustotal.py           # VirusTotal API client
│   ├── abuseipdb.py            # AbuseIPDB API client
│   ├── ipinfo.py               # IPInfo API client
│   ├── spur.py                 # Spur.us API client
│   ├── shodan_client.py        # Shodan API client
│   ├── talos.py                # Cisco Talos API client
│   └── otx.py                  # AlienVault OTX API client
├── utils/
│   ├── ioc_extractor.py        # IOC extraction patterns
│   └── console_output.py       # Rich console formatting
├── sample_alerts/
│   └── datadog_sample.json     # Example alert for testing
├── main.py                     # CLI entry point
├── investigate.py              # Investigation module API
├── config.py                   # Configuration management
└── requirements.txt            # Python dependencies
```

## Supported IOC Types

| Type | Description | Example |
|------|-------------|---------|
| IP Address | IPv4 addresses | `185.220.101.45` |
| Domain | Domain names | `malicious-domain.com` |
| URL | Full URLs | `https://evil.com/payload` |
| MD5 | MD5 file hashes | `44d88612fea8a8f36de82e1278abb02f` |
| SHA1 | SHA1 file hashes | `da39a3ee5e6b4b0d3255bfef95601890afd80709` |
| SHA256 | SHA256 file hashes | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| Email | Email addresses | `admin@example.com` |
| Username | User identifiers | `admin` |
| CVE | Vulnerability IDs | `CVE-2024-1234` |

## Threat Intelligence Platforms

| Platform | Coverage | Key Data Points |
|----------|----------|-----------------|
| **VirusTotal** | IPs, Domains, URLs, File Hashes | Malicious/suspicious verdicts from 70+ security vendors |
| **AbuseIPDB** | IP Addresses | Abuse confidence score, report history, ISP info |
| **IPInfo** | IP Addresses | Geolocation, ASN, VPN/Proxy/Tor detection, hosting detection |
| **Spur** | IP Addresses | Residential proxy detection, VPN/Tor identification, anonymity services |
| **Shodan** | IPs, Domains | Open ports, services, vulnerabilities (CVEs), hosting info |
| **Talos** | IPs, Domains | Reputation scores, threat categories, blacklist status |
| **OTX** | IPs, Domains, URLs, Hashes | Community threat pulses, malware associations, IOC correlations |

### Platform Capabilities

**VirusTotal**
- Multi-engine malware detection for files
- Domain and URL reputation
- IP address reputation from security vendors

**AbuseIPDB**
- Community-reported abuse data
- Confidence scoring based on report volume
- Historical abuse patterns

**IPInfo**
- Accurate geolocation data
- Privacy detection (VPN, Proxy, Tor, iCloud Relay)
- Hosting/datacenter identification
- ASN and organization details

**Spur.us**
- Advanced residential proxy detection
- VPN service identification with operator names
- Tor exit node detection
- Anonymous infrastructure mapping
- Client behavior analysis

**Shodan**
- Internet-wide port scanning data
- Service and product version detection
- Known vulnerability (CVE) identification
- SSL/TLS certificate information
- Historical scan data

**Cisco Talos**
- IP and domain reputation scoring
- Threat category classification (Malware, Phishing, Spam, Botnet)
- Blacklist aggregation
- Email reputation data

**AlienVault OTX**
- Community-sourced threat intelligence pulses
- IOC correlation across indicators
- Malware sample associations
- Threat actor tracking and attribution

## Detection Capabilities

### Account Takeover
- Device fingerprint analysis (JA3/JA4)
- Impossible travel detection
- Proxy/VPN detection (residential, datacenter, Tor)
- Geographic anomaly analysis

### Brute Force & Credential Attacks
- Failed authentication patterns
- Credential stuffing indicators
- Password spray detection

### Malware & Threat Infrastructure
- File hash reputation lookups
- Suspicious domain detection
- Known C2 infrastructure identification

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| httpx | >=0.27.0 | Async HTTP client for API calls |
| rich | >=13.0.0 | Console formatting and output |
| pydantic | >=2.0.0 | Data validation and parsing |
| python-dotenv | >=1.0.0 | Environment variable loading |

## Security Notes

- API keys should never be committed to version control
- Internal IPs (RFC1918, localhost) are automatically excluded from external lookups
- This tool is designed for **defensive security investigation only**
- Alert data may contain sensitive information - handle appropriately
