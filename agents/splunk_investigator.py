"""Splunk Investigator - Tier 2: Queries Splunk logs for investigation."""

from typing import Any, Dict, List, Optional

from models.alert import DataDogAlert
from models.ioc import IOC, IOCType
from models.finding import Finding, FindingSource, RiskLevel
from tools.splunk_tools import SplunkTools
from utils.console_output import ConsoleOutput


class SplunkInvestigator:
    """
    Tier 2 Splunk Investigator.

    Generates Splunk queries for IOCs. Queries are executed via MCP
    by the orchestrating Claude session.

    Includes device fingerprint analysis for:
    - Impossible Travel alerts
    - Account Compromise alerts
    - Suspicious Login alerts
    """

    # Alert types that require device fingerprint analysis
    FINGERPRINT_ALERT_TYPES = [
        "impossible_travel",
        "account_compromise",
        "suspicious_login",
        "brute_force",
        "credential_stuffing",
        "new_device",
        "authentication",
    ]

    def __init__(self, console: Optional[ConsoleOutput] = None):
        """Initialize the Splunk Investigator."""
        self.console = console or ConsoleOutput()
        self.splunk_tools = SplunkTools()

    def _detect_alert_type(self, alert: Optional[DataDogAlert]) -> str:
        """
        Detect the type of alert based on title and tags.

        Args:
            alert: DataDog alert object

        Returns:
            Detected alert type string
        """
        if not alert:
            return "unknown"

        title_lower = alert.title.lower() if alert.title else ""
        tags = [t.lower() for t in (alert.tags or [])]
        message_lower = (alert.message or "").lower()

        # Check for impossible travel
        if "impossible travel" in title_lower or "impossible_travel" in tags:
            return "impossible_travel"

        # Check for account compromise
        if any(x in title_lower for x in ["compromise", "takeover", "ato"]):
            return "account_compromise"

        # Check for suspicious login
        if any(x in title_lower for x in ["suspicious login", "suspicious auth"]):
            return "suspicious_login"

        # Check for brute force
        if "brute" in title_lower or "brute-force" in tags:
            return "brute_force"

        # Check for authentication-related
        if any(x in title_lower for x in ["login", "auth", "authentication"]):
            return "authentication"

        # Check tags
        if any(t in tags for t in ["authentication", "auth", "login", "identity"]):
            return "authentication"

        return "unknown"

    def _should_include_fingerprint_analysis(self, alert_type: str) -> bool:
        """
        Determine if fingerprint analysis should be included based on alert type.

        Args:
            alert_type: Detected alert type

        Returns:
            True if fingerprint analysis should be included
        """
        return alert_type in self.FINGERPRINT_ALERT_TYPES

    def get_queries_for_investigation(
        self,
        iocs: List[IOC],
        alert: Optional[DataDogAlert] = None,
    ) -> List[Dict[str, str]]:
        """
        Generate Splunk queries for the given IOCs.

        Automatically includes device fingerprint analysis for:
        - Impossible Travel alerts
        - Account Compromise alerts
        - Authentication-related alerts

        Args:
            iocs: List of IOCs to investigate
            alert: Optional alert for context

        Returns:
            List of query specifications ready for MCP execution
        """
        if not iocs:
            return []

        # Detect alert type and determine if fingerprint analysis is needed
        alert_type = self._detect_alert_type(alert)
        include_fingerprints = self._should_include_fingerprint_analysis(alert_type)

        # Generate queries with or without fingerprint analysis
        queries = self.splunk_tools.get_queries_for_iocs(
            iocs,
            alert_type=alert_type,
            include_fingerprint_analysis=include_fingerprints,
        )

        # Add timeline query if we have an alert
        if alert and iocs:
            timeline_query = self.splunk_tools.build_timeline_query(
                iocs=iocs,
                alert_time=alert.timestamp,
                window_minutes=60,
            )
            if timeline_query:
                queries.append({
                    "query": timeline_query,
                    "description": "Timeline analysis around alert time",
                    "ioc_value": None,
                })

        return queries

    def create_finding_from_result(
        self,
        query: str,
        description: str,
        result: Dict[str, Any],
        ioc_value: Optional[str] = None,
        analysis_type: Optional[str] = None,
    ) -> Finding:
        """
        Create a finding from Splunk query results.

        Args:
            query: The SPL query that was executed
            description: Description of what this query searched for
            result: Splunk query results
            ioc_value: Associated IOC value if any
            analysis_type: Type of analysis (e.g., 'device_fingerprint', 'risk_assessment')

        Returns:
            Finding object with analysis
        """
        data = result.get("data", [])
        count = result.get("count", len(data) if isinstance(data, list) else 0)

        # Handle fingerprint analysis results separately
        if analysis_type and analysis_type.startswith(("device_", "fingerprint", "impossible_travel", "ip_fingerprint", "risk_")):
            return self._create_fingerprint_finding(query, description, result, ioc_value, analysis_type)

        if count == 0:
            return Finding(
                source=FindingSource.SPLUNK,
                title=f"No events found: {description}",
                description=f"Query: {query}\nNo matching events in the search timeframe.",
                risk_level=RiskLevel.INFO,
                ioc_value=ioc_value,
                raw_data=result,
                confidence=0.5,
            )

        # Determine risk level based on event count
        if count > 100:
            risk_level = RiskLevel.HIGH
            confidence = 0.85
        elif count > 50:
            risk_level = RiskLevel.MEDIUM
            confidence = 0.75
        elif count > 10:
            risk_level = RiskLevel.LOW
            confidence = 0.65
        else:
            risk_level = RiskLevel.INFO
            confidence = 0.6

        # Check for suspicious indicators in the data
        suspicious_indicators = self._check_suspicious_indicators(data)
        if suspicious_indicators:
            if risk_level == RiskLevel.INFO:
                risk_level = RiskLevel.LOW
            confidence = max(confidence, 0.7)

        description_text = f"Query: {query}\n{count} events found."
        if suspicious_indicators:
            description_text += f"\n\nSuspicious indicators:\n{suspicious_indicators}"

        return Finding(
            source=FindingSource.SPLUNK,
            title=f"Found {count} events: {description}",
            description=description_text,
            risk_level=risk_level,
            ioc_value=ioc_value,
            raw_data=result,
            confidence=confidence,
        )

    def _create_fingerprint_finding(
        self,
        query: str,
        description: str,
        result: Dict[str, Any],
        ioc_value: Optional[str],
        analysis_type: str,
    ) -> Finding:
        """
        Create a finding from device fingerprint analysis results.

        This method interprets fingerprint data to determine:
        - If multiple IPs share the same device fingerprint (reduces risk)
        - If a new/unknown device is detected (increases risk)
        - If fingerprints are consistent with historical behavior

        Args:
            query: The SPL query executed
            description: Query description
            result: Query results
            ioc_value: Associated IOC
            analysis_type: Type of fingerprint analysis

        Returns:
            Finding with fingerprint-specific risk assessment
        """
        data = result.get("data", [])
        count = len(data) if isinstance(data, list) else 0

        if count == 0:
            return Finding(
                source=FindingSource.SPLUNK,
                title=f"No fingerprint data: {description}",
                description=f"No device fingerprint data found.\nThis could indicate:\n- User has no recent login history\n- TLS fingerprinting not available for these events",
                risk_level=RiskLevel.INFO,
                ioc_value=ioc_value,
                raw_data=result,
                confidence=0.5,
            )

        # Analyze fingerprint results based on analysis type
        if analysis_type == "impossible_travel_comparison":
            return self._analyze_impossible_travel_fingerprints(data, description, ioc_value, result)
        elif analysis_type == "device_fingerprint":
            return self._analyze_device_baseline(data, description, ioc_value, result)
        elif analysis_type == "device_ip_mapping":
            return self._analyze_device_ip_mapping(data, description, ioc_value, result)
        elif analysis_type == "risk_assessment":
            return self._analyze_auth0_risk(data, description, ioc_value, result)
        elif analysis_type == "comprehensive_fingerprint":
            return self._analyze_comprehensive_fingerprint(data, description, ioc_value, result)
        else:
            # Generic fingerprint finding
            return Finding(
                source=FindingSource.SPLUNK,
                title=f"Device fingerprint data: {description}",
                description=f"Found {count} fingerprint records.\nReview data for device consistency.",
                risk_level=RiskLevel.INFO,
                ioc_value=ioc_value,
                raw_data=result,
                confidence=0.6,
            )

    def _analyze_impossible_travel_fingerprints(
        self,
        data: List[Dict[str, Any]],
        description: str,
        ioc_value: Optional[str],
        raw_result: Dict[str, Any],
    ) -> Finding:
        """Analyze fingerprint comparison between IPs for impossible travel."""
        shared_fingerprints = []
        unique_fingerprints = []

        for row in data:
            fingerprint_shared = str(row.get("fingerprint_shared", ""))
            ja4 = row.get("ja4", "unknown")
            ip_count = row.get("ip_count", 1)

            if "YES" in fingerprint_shared or int(ip_count) > 1:
                shared_fingerprints.append(ja4)
            else:
                unique_fingerprints.append(ja4)

        if shared_fingerprints:
            # Same device from multiple IPs - likely FALSE POSITIVE
            return Finding(
                source=FindingSource.SPLUNK,
                title="SAME DEVICE detected across multiple IPs",
                description=f"Device fingerprint analysis shows the SAME device accessed from multiple IP addresses.\n\n"
                           f"Shared fingerprints: {len(shared_fingerprints)}\n"
                           f"JA4 values: {', '.join(shared_fingerprints[:3])}\n\n"
                           f"This strongly suggests the impossible travel alert is a FALSE POSITIVE.\n"
                           f"The user likely has a device with changing IP (mobile, VPN, satellite internet).",
                risk_level=RiskLevel.LOW,
                ioc_value=ioc_value,
                raw_data=raw_result,
                confidence=0.85,
            )
        else:
            # Different devices from different IPs - potentially suspicious
            return Finding(
                source=FindingSource.SPLUNK,
                title="DIFFERENT DEVICES detected from suspicious IPs",
                description=f"Device fingerprint analysis shows DIFFERENT devices from the suspicious IP addresses.\n\n"
                           f"Unique fingerprints per IP: {len(unique_fingerprints)}\n\n"
                           f"This indicates different physical devices, which increases the risk of:\n"
                           f"- Account compromise\n"
                           f"- Credential sharing\n"
                           f"- Actual impossible travel (different people)",
                risk_level=RiskLevel.HIGH,
                ioc_value=ioc_value,
                raw_data=raw_result,
                confidence=0.8,
            )

    def _analyze_device_baseline(
        self,
        data: List[Dict[str, Any]],
        description: str,
        ioc_value: Optional[str],
        raw_result: Dict[str, Any],
    ) -> Finding:
        """Analyze historical device fingerprint baseline."""
        unique_fingerprints = len(data)
        total_ips = set()

        for row in data:
            ips = row.get("ips", [])
            if isinstance(ips, list):
                total_ips.update(ips)
            elif isinstance(ips, str):
                total_ips.add(ips)

        description_text = (
            f"Historical device fingerprint baseline:\n\n"
            f"- Unique device fingerprints (JA4): {unique_fingerprints}\n"
            f"- Total unique IPs observed: {len(total_ips)}\n\n"
        )

        if unique_fingerprints <= 3:
            description_text += "User has a consistent device profile (1-3 devices). Good baseline for comparison."
            risk_level = RiskLevel.INFO
        elif unique_fingerprints <= 6:
            description_text += "User has moderate device diversity (4-6 devices). May use multiple browsers/devices."
            risk_level = RiskLevel.INFO
        else:
            description_text += "User has high device diversity (7+ fingerprints). Could indicate device spoofing or many devices."
            risk_level = RiskLevel.LOW

        return Finding(
            source=FindingSource.SPLUNK,
            title=f"Device baseline: {unique_fingerprints} unique fingerprints",
            description=description_text,
            risk_level=risk_level,
            ioc_value=ioc_value,
            raw_data=raw_result,
            confidence=0.75,
        )

    def _analyze_device_ip_mapping(
        self,
        data: List[Dict[str, Any]],
        description: str,
        ioc_value: Optional[str],
        raw_result: Dict[str, Any],
    ) -> Finding:
        """Analyze device-to-IP mapping patterns."""
        multi_ip_devices = []
        single_ip_devices = []

        for row in data:
            unique_ips = int(row.get("unique_ips", 1))
            ja4 = row.get("ja4", "unknown")[:20]
            user_agent = row.get("user_agent", "unknown")[:50]

            if unique_ips > 1:
                multi_ip_devices.append({"ja4": ja4, "ips": unique_ips, "ua": user_agent})
            else:
                single_ip_devices.append({"ja4": ja4, "ua": user_agent})

        description_text = "Device-to-IP mapping analysis:\n\n"

        if multi_ip_devices:
            description_text += f"Devices seen from MULTIPLE IPs ({len(multi_ip_devices)}):\n"
            for dev in multi_ip_devices[:3]:
                description_text += f"  - {dev['ua']}: {dev['ips']} unique IPs\n"
            description_text += "\nThis is NORMAL for mobile devices, VPNs, or satellite internet.\n"

        if single_ip_devices:
            description_text += f"\nDevices seen from SINGLE IP ({len(single_ip_devices)}):\n"
            for dev in single_ip_devices[:2]:
                description_text += f"  - {dev['ua']}\n"

        return Finding(
            source=FindingSource.SPLUNK,
            title=f"Device-IP mapping: {len(multi_ip_devices)} multi-IP devices",
            description=description_text,
            risk_level=RiskLevel.INFO,
            ioc_value=ioc_value,
            raw_data=raw_result,
            confidence=0.7,
        )

    def _analyze_auth0_risk(
        self,
        data: List[Dict[str, Any]],
        description: str,
        ioc_value: Optional[str],
        raw_result: Dict[str, Any],
    ) -> Finding:
        """Analyze Auth0's built-in risk assessments."""
        high_risk_events = []
        impossible_travel_flags = []

        for row in data:
            risk_overall = str(row.get("risk_overall", "")).lower()
            risk_travel = str(row.get("risk_impossible_travel", ""))
            risk_device = str(row.get("risk_new_device", ""))
            ip = row.get("ip", "unknown")

            if risk_overall in ["low", "medium"]:
                if "impossible" in risk_travel.lower():
                    impossible_travel_flags.append({"ip": ip, "assessment": risk_travel})
            if risk_overall == "high":
                high_risk_events.append({"ip": ip, "travel": risk_travel, "device": risk_device})

        description_text = "Auth0 Risk Assessment Analysis:\n\n"

        if not high_risk_events and not impossible_travel_flags:
            description_text += "No high-risk events detected by Auth0.\nAll recent logins passed risk assessment."
            risk_level = RiskLevel.LOW
        elif high_risk_events:
            description_text += f"HIGH RISK events detected: {len(high_risk_events)}\n"
            for event in high_risk_events[:3]:
                description_text += f"  - IP {event['ip']}: travel={event['travel']}, device={event['device']}\n"
            risk_level = RiskLevel.MEDIUM
        else:
            description_text += f"Impossible travel flags: {len(impossible_travel_flags)}\n"
            description_text += "Auth0 detected travel anomalies but overall risk was acceptable."
            risk_level = RiskLevel.LOW

        return Finding(
            source=FindingSource.SPLUNK,
            title=f"Auth0 Risk: {len(high_risk_events)} high-risk events",
            description=description_text,
            risk_level=risk_level,
            ioc_value=ioc_value,
            raw_data=raw_result,
            confidence=0.8,
        )

    def _analyze_comprehensive_fingerprint(
        self,
        data: List[Dict[str, Any]],
        description: str,
        ioc_value: Optional[str],
        raw_result: Dict[str, Any],
    ) -> Finding:
        """
        Analyze comprehensive device fingerprint data grouped by IP.

        This method processes results from the comprehensive fingerprint query which
        provides per-IP analysis including:
        - Device type classification
        - JA3/JA4 fingerprint counts and values
        - User agent details
        - Auth0 device status
        - Event counts and timestamps

        Args:
            data: Query results grouped by IP
            description: Query description
            ioc_value: Associated IOC (usually email)
            raw_result: Full query result

        Returns:
            Finding with comprehensive fingerprint analysis
        """
        if not data:
            return Finding(
                source=FindingSource.DEVICE_FINGERPRINT,
                title="No device fingerprint data found",
                description="No JA4 fingerprint data available for this user in the past 90 days.",
                risk_level=RiskLevel.INFO,
                ioc_value=ioc_value,
                raw_data=raw_result,
                confidence=0.5,
            )

        # Analyze the fingerprint data
        unique_ips = len(data)
        device_types = {}
        shared_fingerprints = {}  # JA4 -> list of IPs
        ip_details = []

        for row in data:
            ip = row.get("ip", "unknown")
            device_type = row.get("device_type", "Unknown")
            ja4_list = row.get("ja4_fingerprints", [])
            unique_ja4 = int(row.get("unique_ja4_count", 1))
            event_count = int(row.get("event_count", 0))
            device_status = row.get("device_status", "unknown")
            user_agents = row.get("user_agents", [])

            # Track device types
            device_types[device_type] = device_types.get(device_type, 0) + 1

            # Track JA4 fingerprints across IPs
            if isinstance(ja4_list, list):
                for ja4 in ja4_list:
                    if ja4 not in shared_fingerprints:
                        shared_fingerprints[ja4] = []
                    shared_fingerprints[ja4].append(ip)
            elif isinstance(ja4_list, str):
                if ja4_list not in shared_fingerprints:
                    shared_fingerprints[ja4_list] = []
                shared_fingerprints[ja4_list].append(ip)

            ip_details.append({
                "ip": ip,
                "device_type": device_type,
                "unique_ja4": unique_ja4,
                "events": event_count,
                "status": device_status,
                "user_agent": user_agents[0] if isinstance(user_agents, list) and user_agents else str(user_agents)[:80],
            })

        # Check for fingerprints shared across multiple IPs (same device, different locations)
        multi_ip_fingerprints = {ja4: ips for ja4, ips in shared_fingerprints.items() if len(ips) > 1}

        # Build analysis description
        description_text = f"Comprehensive Device Fingerprint Analysis (90 days)\n"
        description_text += f"{'=' * 50}\n\n"

        # Summary
        description_text += f"SUMMARY:\n"
        description_text += f"  - Unique IPs: {unique_ips}\n"
        description_text += f"  - Device Types: {', '.join(f'{k} ({v})' for k, v in device_types.items())}\n"
        description_text += f"  - Unique JA4 Fingerprints: {len(shared_fingerprints)}\n\n"

        # Per-IP breakdown
        description_text += f"PER-IP BREAKDOWN:\n"
        for detail in ip_details[:10]:  # Limit to top 10
            description_text += f"  [{detail['device_type']}] {detail['ip']}\n"
            description_text += f"      JA4 variants: {detail['unique_ja4']}, Events: {detail['events']}, Status: {detail['status']}\n"

        # Risk assessment based on findings
        risk_level = RiskLevel.INFO
        confidence = 0.75

        # Check for same device from multiple IPs (reduces impossible travel risk)
        if multi_ip_fingerprints:
            description_text += f"\nSAME DEVICE FROM MULTIPLE IPs ({len(multi_ip_fingerprints)} fingerprints):\n"
            for ja4, ips in list(multi_ip_fingerprints.items())[:3]:
                description_text += f"  - JA4 {ja4[:20]}... seen from {len(ips)} IPs\n"
            description_text += "\n  This suggests the user has devices with changing IPs (mobile, VPN).\n"
            description_text += "  Reduces risk of impossible travel being malicious.\n"
            risk_level = RiskLevel.LOW
            confidence = 0.85

        # Check for multiple different device types (increases risk if unexpected)
        if len(device_types) > 1:
            description_text += f"\nMULTIPLE DEVICE TYPES DETECTED:\n"
            for dtype, count in device_types.items():
                description_text += f"  - {dtype}: {count} IP(s)\n"

            # If we have both desktop and mobile with no shared fingerprints, higher risk
            has_desktop = any(t in device_types for t in ["Windows/Desktop", "macOS"])
            has_mobile = any(t in device_types for t in ["iPhone/iOS", "Android"])
            if has_desktop and has_mobile and not multi_ip_fingerprints:
                description_text += "\n  Different device types with NO shared fingerprints.\n"
                description_text += "  This could indicate account sharing or compromise.\n"
                risk_level = RiskLevel.MEDIUM
                confidence = 0.8

        return Finding(
            source=FindingSource.DEVICE_FINGERPRINT,
            title=f"Device Fingerprint Analysis: {unique_ips} IPs, {len(device_types)} device types",
            description=description_text,
            risk_level=risk_level,
            ioc_value=ioc_value,
            raw_data=raw_result,
            confidence=confidence,
        )

    def _check_suspicious_indicators(self, data: List[Dict[str, Any]]) -> str:
        """Check query results for suspicious indicators."""
        if not data or not isinstance(data, list):
            return ""

        indicators = set()

        for event in data[:20]:
            if not isinstance(event, dict):
                continue

            status = str(event.get("status", "")).lower()
            action = str(event.get("action", "")).lower()

            if "fail" in status or "fail" in action:
                indicators.add("Failed authentication attempts detected")
            if "denied" in status or "denied" in action:
                indicators.add("Access denied events detected")
            if "error" in status:
                indicators.add("Error events detected")

            user_agent = str(event.get("user_agent", "")).lower()
            if any(x in user_agent for x in ["curl", "wget", "python", "scanner"]):
                indicators.add("Suspicious user agent detected")

        return "\n".join(f"- {ind}" for ind in list(indicators)[:5])
