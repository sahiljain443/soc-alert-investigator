# SOC Alert Investigator

Automated security alert investigation system designed to run within Claude Code sessions.

## Architecture

Four-tier agent system with strict separation of concerns, orchestrated by `workflow.py`:

```
workflow.py  (Auto-pilot entry point for Claude Code sessions)
    │
Tier 0: SignalAcquisitionAgent (agents/signal_acquisition.py)
    └── Acquires alerts from DataDog, file, stdin, or raw dict
    │
Tier 1: Orchestrator (agents/orchestrator.py)
    ├── Parses alerts, extracts IOCs, coordinates workflow
    │
Tier 2: Investigators
    ├── SplunkInvestigator (agents/splunk_investigator.py)
    │   └── Generates SPL queries, analyzes results, detects attack patterns
    ├── ThreatIntelEnricher (agents/threat_intel.py)
    │   └── Enriches IOCs via 8 threat intel sources (see below)
    │
Tier 3: Reporter (agents/reporter.py)
    └── Consolidates findings, calculates risk, generates recommendations

Utilities:
    ├── utils/alert_classifier.py  # Canonical ATO keyword detection
    └── utils/mcp_normalizer.py    # Normalizes MCP Splunk responses
```

## Investigation Workflow

1. Acquire alert via `SignalAcquisitionAgent` (DataDog API, file, stdin, or raw dict)
2. Parse DataDog alert JSON into `DataDogAlert` model
3. Extract IOCs using regex patterns (`utils/ioc_extractor.py`)
4. Generate Splunk queries for each IOC type
5. **Claude executes queries via MCP** (`mcp__splunk__run_splunk_query`)
6. Enrich external IOCs with threat intelligence (async)
7. Analyze device fingerprints for account takeover detection
8. Generate risk-scored investigation report

## Signal Acquisition (Tier 0)

The `SignalAcquisitionAgent` (`agents/signal_acquisition.py`) unifies all alert input sources behind a single agent interface. It supports six source types via the `SignalSource` enum:

| Source | Method | Description |
|--------|--------|-------------|
| `DATADOG` | `acquire_from_datadog()` | Interactive DataDog signal selection |
| `DATADOG_ID` | `acquire_from_datadog_id(id)` | Direct fetch by signal ID |
| `FILE` | `acquire_from_file(path)` | Load JSON from file |
| `RAW_DICT` | `acquire_from_dict(data)` | Pass-through for programmatic use |
| `STDIN` | `acquire_from_stdin()` | Read JSON from stdin |
| `SAMPLE` | `acquire_from_dict(SAMPLE_ALERT)` | Built-in sample alert |

All acquisition failures raise `SignalAcquisitionError`. DataDog imports are lazy (inside methods) so the agent can be instantiated without DD_API_KEY/DD_APP_KEY -- only DataDog methods fail if keys are missing.

Module-level convenience functions are also available:
- `acquire_from_file(path)`
- `acquire_from_dict(data)`
- `acquire_from_datadog_id(id)`

Non-interactive methods (used by auto-pilot workflow):
- `list_signals_for_selection(hours, severity, limit, open_only)` -- returns `{"signals": [...], "raw_signals": [...], "count": int}`
- `select_signal(raw_signals, index)` -- returns mapped alert dict by 1-based index

The Orchestrator holds a reference at `self.signal_acquisition`.

## DataDog Integration

The `datadog_connector/` module provides integration with DataDog Security Monitoring API:

```
datadog_connector/
├── client.py          # DataDog Security API client (uses httpx)
├── signal_selector.py # Interactive CLI for browsing/selecting signals
└── signal_mapper.py   # Maps DataDog signal format → DataDogAlert model
```

### Configuration

Set these environment variables for DataDog integration:

```bash
DD_API_KEY=<your-datadog-api-key>
DD_APP_KEY=<your-datadog-app-key>
DD_SITE=datadoghq.com  # or datadoghq.eu, us3.datadoghq.com, etc.
```

### CLI Usage

```bash
# Interactive signal selection (recommended for manual triage)
python main.py --datadog

# Filter by severity
python main.py --datadog --datadog-severity high

# Only show open/untriaged signals
python main.py --datadog --datadog-open

# List signals without investigating
python main.py --datadog --datadog-list

# Investigate a specific signal by ID
python main.py --datadog-id <signal-id>

# Adjust time window (default: 24 hours)
python main.py --datadog --datadog-hours 72
```

### Signal Mapping

The `SignalMapper` transforms DataDog's nested signal structure into the flat format expected by `DataDogAlert.from_raw()`:

| DataDog Signal Field | DataDogAlert Field |
|---------------------|-------------------|
| `id` | `id` |
| `attributes.message` | `message` |
| `attributes.rule.name` | `title` |
| `attributes.severity` | `severity` |
| `attributes.status` | `status` |
| `attributes.timestamp` | `timestamp` |
| `attributes.tags` | `tags` |
| `attributes.attributes.network.client.ip` | `attributes.source_ip` |
| `attributes.attributes.usr.email` | `attributes.user_email` |

## Coding Conventions

- **Models**: Use Pydantic for all data structures (`models/`)
- **Async**: Threat intel enrichment uses `asyncio` for concurrent API calls
- **Error Handling**: Graceful degradation - missing API keys or failed lookups should not crash the investigation
- **IOC Classification**: Internal vs external determined by IP ranges and domain patterns
- **Risk Levels**: CRITICAL, HIGH, MEDIUM, LOW, INFO (defined in `models/finding.py`)

## MCP Tool Usage

Splunk queries are prepared but not executed directly. The workflow expects Claude to:

```python
# Execute prepared queries via MCP
result = mcp__splunk__run_splunk_query(
    query="index=auth user=... | stats count by src_ip",
    earliest_time="-24h",
    latest_time="now"
)
```

Query results feed back into `SplunkInvestigator.analyze_results()` for finding generation.

## Threat Intelligence Sources

Eight concurrent threat intel enrichment sources for IP addresses, domains, URLs, and file hashes:

| Source | IOC Types | Key Capabilities |
|--------|-----------|------------------|
| **VirusTotal** | IP, Domain, URL, Hash | Multi-engine malware verdicts |
| **AbuseIPDB** | IP | Community abuse reports, confidence scoring |
| **IPInfo** | IP | Geolocation, VPN/Proxy/Tor detection |
| **Spur.us** | IP | Residential proxy detection, anonymity services |
| **Shodan** | IP, Domain | Open ports, vulnerabilities, services |
| **Talos** | IP, Domain | Reputation scoring, threat categories |
| **OTX** | IP, Domain, URL, Hash | Community threat pulses, malware associations |
| **RH-ISAC** | IP, Domain, URL, Hash | Retail/hospitality sector community intel via MISP |

## Security Considerations

- Never log or expose API keys (VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, IPINFO_API_KEY, SPUR_API_KEY, SHODAN_API_KEY, TALOS_API_KEY, OTX_API_KEY, RHISAC_API_KEY, DD_API_KEY, DD_APP_KEY)
- Internal IPs (RFC1918, localhost) are excluded from external threat intel lookups
- This tool is for **defensive investigation only** - do not modify for offensive use
- Alert data may contain sensitive information - handle appropriately

## Key Detection Capabilities

- **Account Takeover**: Device fingerprint analysis (JA3/JA4), impossible travel, proxy detection
- **Brute Force**: Failed authentication patterns, credential stuffing indicators
- **Malware**: File hash reputation, suspicious domains, known C2 infrastructure

## Device Fingerprint Analysis

For impossible travel, account takeover, or suspicious login investigations, use the comprehensive device fingerprint query:

```spl
index=auth0 sourcetype=auth0 "{email}"
| spath
| eval ip=coalesce('data.ip', 'data.client_ip')
| eval ja3='data.security_context.ja3'
| eval ja4='data.security_context.ja4'
| eval user_agent='data.user_agent'
| eval event_type='data.type'
| eval device_status='data.details.riskAssessment.assessments.NewDevice.details.device'
| where isnotnull(ja4)
| stats
    count as event_count,
    dc(ja3) as unique_ja3_count,
    dc(ja4) as unique_ja4_count,
    values(ja3) as ja3_fingerprints,
    values(ja4) as ja4_fingerprints,
    values(user_agent) as user_agents,
    values(device_status) as device_status,
    min(_time) as first_seen,
    max(_time) as last_seen
    by ip
| eval device_type=case(
    match(user_agents, "iPhone"), "iPhone/iOS",
    match(user_agents, "Windows"), "Windows/Desktop",
    match(user_agents, "Android"), "Android",
    match(user_agents, "Mac"), "macOS",
    true(), "Unknown"
)
| table ip, device_type, ja4_fingerprints, unique_ja4_count, ja3_fingerprints, unique_ja3_count, user_agents, device_status, event_count, first_seen, last_seen
| sort -event_count
```

**Time range**: Use `-90d` (default) for comprehensive baseline analysis.

This query is available via `SplunkTools.build_comprehensive_device_fingerprint_query(email)` and provides:
- Per-IP fingerprint grouping
- Device type auto-classification
- JA3/JA4 fingerprint counts and values
- Auth0 device status
- Timeline data (first/last seen)

## Auto-Pilot Workflow (`workflow.py`)

The `InvestigationWorkflow` class provides a 5-step non-interactive flow designed for Claude Code sessions. After signal selection, the entire investigation runs on auto-pilot.

### Steps

| Step | Method | Runs in | What happens |
|------|--------|---------|-------------|
| 1 | `step_1_list_signals()` | Subagent | Fetches DataDog signals, returns structured list (no stdin) |
| 2 | `step_2_select_and_plan()` | Subagent | Selects signal by index, parses alert, extracts IOCs, generates Splunk queries |
| 2b | `step_2_plan_from_alert_data()` | Subagent | Alternative: builds plan from file/dict/ID instead of list selection |
| 3 | `step_3_process_splunk_results()` | Subagent | Converts raw MCP Splunk responses into Finding objects |
| 4 | `step_4_enrich_iocs_sync()` | Subagent | Enriches external IOCs via 8 threat intel sources (parallel) |
| 5 | `step_5_generate_report()` | **Main session** | Generates risk-scored Rich-formatted report |

### Report Generation (Step 5) -- MUST Run in Main Session

Step 5 calls `Reporter.generate_report()` which uses the `InvestigationPresenter` (Rich library) to render a formatted report directly to the terminal. **This step MUST execute as a direct Bash command in the main Claude Code session, NOT inside a Task subagent.**

If step 5 runs inside a Task subagent, the Rich output is captured in the subagent's sandboxed stdout and never reaches the user's terminal. The user would only see a plain-text markdown summary instead of the professional Rich-formatted report.

**Correct pattern**: The SOC investigation subagent (steps 1-4) should serialize and return the `plan` and `all_findings` data. The main session then runs step 5 as a direct Bash call:

```bash
python3 -c "
import json, pickle, sys
from workflow import InvestigationWorkflow

wf = InvestigationWorkflow()

# Deserialize plan and findings from subagent output
plan = ...      # reconstructed plan dict
findings = ...  # reconstructed Finding objects

# This prints Rich-formatted report directly to terminal
report = wf.step_5_generate_report(plan, findings)
"
```

The subagent should save intermediate state (plan + findings) to a temporary JSON file so the main session can load and pass it to step 5.

### Claude Code Flow

Steps 1-4 run inside the SOC subagent (Task tool). The subagent executes Splunk queries via MCP, runs threat intel enrichment, and **saves serialized results to a temp file**.

```python
# --- Inside SOC subagent (steps 1-4) ---
from workflow import InvestigationWorkflow
import json

wf = InvestigationWorkflow()

# 1. List signals
signals = wf.step_1_list_signals(hours=24, severity="high")

# 2. User picks signal → build plan
plan = wf.step_2_select_and_plan(signals["raw_signals"], index=1)

# 3. Execute each query via MCP, collect results
splunk_results = []
for q in plan["queries"]:
    result = mcp__splunk__run_splunk_query(
        query=q["query"],
        earliest_time=q.get("earliest_time", "-24h"),
        latest_time=q.get("earliest_time", "now"),
    )
    splunk_results.append(result)

findings = wf.step_3_process_splunk_results(plan, splunk_results)

# 4. Threat intel enrichment
ti_findings = wf.step_4_enrich_iocs_sync(plan)

all_findings = findings + ti_findings

# Save state for main session to pick up
# (subagent returns file path in its response)
```

Step 5 runs as a **direct Bash call** in the main Claude Code session:

```python
# --- Main session (step 5) ---
# Load serialized plan + findings from subagent output
from workflow import InvestigationWorkflow

wf = InvestigationWorkflow()
report = wf.step_5_generate_report(plan, all_findings)
# Rich output goes directly to user's terminal
```

### MCP Result Normalization

The `utils/mcp_normalizer.py` module handles all MCP response variants:
- `{"data": [...]}` -- canonical, passed through
- `{"results": [...]}` -- `results` renamed to `data`
- Plain list -- wrapped in `{"data": <list>, "count": <len>}`
- `None` / error string -- returns empty result with optional `"error"` key

Use `normalize_mcp_splunk_result(raw)` before passing to `SplunkInvestigator.create_finding_from_result()`. The workflow's step 3 does this automatically.

### MCP Retry Guidance

If `mcp__splunk__run_splunk_query` returns an error or empty result:
1. Check the SPL syntax (missing quotes, unescaped characters)
2. Widen the time range (e.g. `-7d` instead of `-24h`)
3. Retry once; if it still fails, move on -- the reporter handles missing data gracefully

## Do Not

- Break tier separation - each tier has specific responsibilities
- Execute Splunk queries directly in Python - use MCP tools
- Skip IOC validation - always use the Pydantic models
- Hardcode credentials - use environment variables via `config.py`
- Remove async patterns from threat intel - concurrent lookups are intentional
- Run step 5 (report generation) inside a Task subagent - Rich output will be lost; always run it as a direct Bash call in the main session
