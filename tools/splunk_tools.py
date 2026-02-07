"""Splunk query tools for investigation."""

import json
import subprocess
from datetime import datetime, timedelta
from typing import Any, Dict, List

from models.ioc import IOC, IOCType
from models.finding import Finding, FindingSource, RiskLevel


class SplunkTools:
    """Splunk query tools using MCP integration."""

    # Common security-relevant indexes
    SECURITY_INDEXES = [
        "auth0",
        "auth0-guest",
        "1password",
        "atlantis",
        "_audit",
    ]

    # Internal domain for corporate users
    INTERNAL_DOMAIN = "toasttab.com"

    def __init__(self):
        """Initialize Splunk tools."""
        pass

    def _is_internal_user(self, identifier: str) -> bool:
        """Check if a user/email belongs to the internal corporate domain."""
        return identifier.lower().endswith(f"@{self.INTERNAL_DOMAIN}")

    def query(
        self,
        spl_query: str,
        earliest_time: str = "-24h",
        latest_time: str = "now",
        row_limit: int = 100,
    ) -> Dict[str, Any]:
        """
        Execute a Splunk query.

        This is a wrapper that will be called by the agent.
        In the actual implementation, this would use the Splunk MCP connection.

        Args:
            spl_query: SPL query to execute
            earliest_time: Start time for search
            latest_time: End time for search
            row_limit: Maximum rows to return

        Returns:
            Query results as a dictionary
        """
        # This method is designed to be called via Claude tool use
        # The actual Splunk MCP integration happens at the agent level
        return {
            "query": spl_query,
            "earliest_time": earliest_time,
            "latest_time": latest_time,
            "row_limit": row_limit,
            "status": "pending",
            "message": "Query prepared for execution via MCP",
        }

    def build_ip_query(self, ip: str, time_range: str = "-24h") -> str:
        """Build SPL query to search for IP activity."""
        indexes = " OR ".join(f'index="{idx}"' for idx in self.SECURITY_INDEXES)
        return f'({indexes}) (src_ip="{ip}" OR dest_ip="{ip}" OR client_ip="{ip}" OR ip="{ip}")'

    def build_auth_ip_query(self, ip: str, time_range: str = "-24h") -> str:
        """Build SPL query to search for authentication events from an IP in Auth0."""
        return f'index=auth0 (ip="{ip}" OR client_ip="{ip}") | stats count by user, type, date, ip, user_agent | sort -count'

    def build_user_query(self, username: str, time_range: str = "-24h") -> str:
        """Build SPL query to search for user activity.

        Uses index=system_audit sourcetype=*okta* for internal (@toasttab.com) users.
        Uses index=auth0 for external users.
        """
        if self._is_internal_user(username):
            # Internal users - query Okta in system_audit
            return f'index=system_audit sourcetype=*okta* (user="{username}" OR user_name="{username}" OR actor.alternateId="{username}")'
        else:
            # External users - query Auth0
            return f'index=auth0 (user="{username}" OR user_name="{username}" OR username="{username}")'

    def build_host_query(self, hostname: str, time_range: str = "-24h") -> str:
        """Build SPL query to search for host activity."""
        indexes = " OR ".join(f'index="{idx}"' for idx in self.SECURITY_INDEXES)
        return f'({indexes}) (host="{hostname}" OR hostname="{hostname}" OR src_host="{hostname}" OR dest_host="{hostname}")'

    def build_email_query(self, email: str, time_range: str = "-24h") -> str:
        """Build SPL query to search for email activity.

        Uses index=system_audit sourcetype=*okta* for internal (@toasttab.com) users.
        Uses index=auth0 for external users.
        """
        if self._is_internal_user(email):
            # Internal users - query Okta in system_audit
            return f'index=system_audit sourcetype=*okta* (user="{email}" OR actor.alternateId="{email}" OR target{{}}..alternateId="{email}")'
        else:
            # External users - query Auth0
            return f'index=auth0 (email="{email}" OR user_email="{email}" OR user.email="{email}")'

    def build_hash_query(self, file_hash: str, hash_type: str = "sha256") -> str:
        """Build SPL query to search for file hash."""
        return f'index=* ({hash_type}="{file_hash}" OR file_hash="{file_hash}" OR hash="{file_hash}")'

    # =========================================================================
    # Device Fingerprint Analysis Queries (for Impossible Travel & Account Compromise)
    # =========================================================================

    def build_device_fingerprint_query(self, email: str, time_range: str = "-90d") -> str:
        """
        Build SPL query to extract device fingerprints (JA3/JA4) for a user.

        JA3/JA4 fingerprints are TLS client fingerprints that help identify
        unique devices/browsers regardless of IP address changes.

        Args:
            email: User email to search for
            time_range: How far back to search (default 90 days for baseline)

        Returns:
            SPL query string
        """
        return f'''index=auth0 "{email}"
| spath input=_raw
| eval ja3='data.security_context.ja3'
| eval ja4='data.security_context.ja4'
| eval user_agent='data.user_agent'
| eval ip='data.ip'
| eval event_type='data.type'
| where isnotnull(ja3)
| stats count, values(ip) as ips, earliest(_time) as first_seen, latest(_time) as last_seen by ja3, ja4, user_agent
| sort -last_seen'''

    def build_device_fingerprint_by_ip_query(self, ip: str, email: str) -> str:
        """
        Build SPL query to get device fingerprints for a specific IP and user.

        Used to compare fingerprints from suspicious IPs against known devices.

        Args:
            ip: IP address to check
            email: User email

        Returns:
            SPL query string
        """
        return f'''index=auth0 "{email}" "{ip}"
| spath input=_raw
| eval ja3='data.security_context.ja3'
| eval ja4='data.security_context.ja4'
| eval user_agent='data.user_agent'
| eval ip='data.ip'
| eval event_time='data.date'
| eval event_type='data.type'
| where isnotnull(ja3)
| table event_time, ip, user_agent, ja3, ja4, event_type
| sort -event_time'''

    def build_device_fingerprint_history_query(self, email: str) -> str:
        """
        Build SPL query to get full device fingerprint history with IP associations.

        This query shows which JA4 fingerprints have been seen from which IPs,
        helping identify if multiple IPs belong to the same device.

        Args:
            email: User email

        Returns:
            SPL query string
        """
        return f'''index=auth0 "{email}"
| spath input=_raw
| eval ja3='data.security_context.ja3'
| eval ja4='data.security_context.ja4'
| eval user_agent='data.user_agent'
| eval ip='data.ip'
| where isnotnull(ja4)
| stats count as login_count,
        dc(ip) as unique_ips,
        values(ip) as all_ips,
        earliest(_time) as first_seen,
        latest(_time) as last_seen
    by ja4, user_agent
| eval days_active=round((last_seen-first_seen)/86400, 1)
| sort -last_seen
| head 20'''

    def build_impossible_travel_fingerprint_query(self, email: str, ip1: str, ip2: str) -> str:
        """
        Build SPL query to compare device fingerprints between two IPs for impossible travel analysis.

        This query helps determine if two geographically distant logins came from
        the same device (likely false positive) or different devices (higher risk).

        Args:
            email: User email
            ip1: First IP address (e.g., from location A)
            ip2: Second IP address (e.g., from location B)

        Returns:
            SPL query string
        """
        return f'''index=auth0 "{email}" ("{ip1}" OR "{ip2}")
| spath input=_raw
| eval ja3='data.security_context.ja3'
| eval ja4='data.security_context.ja4'
| eval user_agent='data.user_agent'
| eval ip='data.ip'
| eval event_time='data.date'
| where isnotnull(ja4)
| stats values(ip) as ips,
        values(user_agent) as user_agents,
        count as events
    by ja4
| eval ip_count=mvcount(ips)
| eval fingerprint_shared=if(ip_count>1, "YES - Same device from multiple IPs", "NO - Single IP")
| table ja4, fingerprint_shared, ip_count, ips, user_agents, events'''

    def build_new_device_detection_query(self, email: str, ja4_fingerprint: str) -> str:
        """
        Build SPL query to check if a JA4 fingerprint is new for a user.

        Args:
            email: User email
            ja4_fingerprint: JA4 fingerprint to check

        Returns:
            SPL query string
        """
        return f'''index=auth0 "{email}"
| spath input=_raw
| eval ja4='data.security_context.ja4'
| where ja4="{ja4_fingerprint}"
| stats count, earliest(_time) as first_seen, latest(_time) as last_seen
| eval is_new=if(first_seen > relative_time(now(), "-7d"), "NEW DEVICE (< 7 days)", "KNOWN DEVICE")'''

    def build_auth0_risk_assessment_query(self, email: str) -> str:
        """
        Build SPL query to extract Auth0's built-in risk assessments for a user.

        Auth0 provides risk scores for ImpossibleTravel, NewDevice, UntrustedIP.

        Args:
            email: User email

        Returns:
            SPL query string
        """
        return f'''index=auth0 "{email}" "riskAssessment"
| spath input=_raw
| eval risk_overall='data.details.riskAssessment.confidence'
| eval risk_impossible_travel='data.details.riskAssessment.assessments.ImpossibleTravel.code'
| eval risk_new_device='data.details.riskAssessment.assessments.NewDevice.code'
| eval risk_untrusted_ip='data.details.riskAssessment.assessments.UntrustedIP.code'
| eval ip='data.ip'
| eval event_time='data.date'
| eval event_type='data.type'
| where isnotnull(risk_overall)
| table event_time, ip, event_type, risk_overall, risk_impossible_travel, risk_new_device, risk_untrusted_ip
| sort -event_time
| head 20'''

    def build_comprehensive_device_fingerprint_query(self, email: str, time_range: str = "-90d") -> str:
        """
        Build comprehensive SPL query for device fingerprint analysis.

        This single query captures all relevant device fingerprint data for investigation:
        - Groups by IP address to show fingerprint consistency per location
        - Counts unique JA3/JA4 fingerprints to detect multiple devices per IP
        - Auto-classifies device type based on user agent
        - Includes Auth0's device status assessment
        - Shows first/last seen timestamps for timeline analysis

        Use this query for:
        - Impossible Travel investigations
        - Account Compromise investigations
        - New Device detection
        - Device baseline establishment

        Args:
            email: User email to analyze
            time_range: Time range for analysis (default: -90d)

        Returns:
            SPL query string
        """
        return f'''index=auth0 sourcetype=auth0 "{email}"
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
| sort -event_count'''

    def build_timeline_query(
        self,
        iocs: List[IOC],
        alert_time: datetime,
        window_minutes: int = 60,
    ) -> str:
        """Build SPL query for timeline analysis around alert time."""
        # Build search terms for all IOCs
        search_terms = []
        for ioc in iocs:
            if ioc.type == IOCType.IP_ADDRESS:
                search_terms.append(f'src_ip="{ioc.value}" OR dest_ip="{ioc.value}"')
            elif ioc.type == IOCType.USERNAME:
                search_terms.append(f'user="{ioc.value}"')
            elif ioc.type == IOCType.EMAIL:
                search_terms.append(f'email="{ioc.value}"')
            elif ioc.type == IOCType.HOSTNAME:
                search_terms.append(f'host="{ioc.value}"')

        if not search_terms:
            return ""

        search_clause = " OR ".join(f"({term})" for term in search_terms)
        indexes = " OR ".join(f'index="{idx}"' for idx in self.SECURITY_INDEXES)

        return f'({indexes}) ({search_clause}) | sort _time | table _time, index, sourcetype, src_ip, dest_ip, user, host, action, status'

    def get_queries_for_iocs(
        self,
        iocs: List[IOC],
        alert_type: str = None,
        include_fingerprint_analysis: bool = True,
    ) -> List[Dict[str, str]]:
        """
        Generate appropriate Splunk queries for a list of IOCs.

        Args:
            iocs: List of IOCs to investigate
            alert_type: Type of alert (e.g., 'impossible_travel', 'account_compromise')
            include_fingerprint_analysis: Whether to include device fingerprint queries

        Returns:
            List of query specifications with query and description
        """
        queries = []

        # Track emails for fingerprint analysis
        email_iocs = []
        ip_iocs = []

        for ioc in iocs:
            if ioc.type == IOCType.IP_ADDRESS and not ioc.is_internal:
                ip_iocs.append(ioc.value)
                # Add general IP query
                queries.append({
                    "query": self.build_ip_query(ioc.value),
                    "description": f"Search for external IP activity: {ioc.value}",
                    "ioc_value": ioc.value,
                })
                # Add Auth0-specific query for authentication events from this IP
                queries.append({
                    "query": self.build_auth_ip_query(ioc.value),
                    "description": f"Search Auth0 logins from IP: {ioc.value}",
                    "ioc_value": ioc.value,
                })
            elif ioc.type == IOCType.IP_ADDRESS and ioc.is_internal:
                queries.append({
                    "query": self.build_ip_query(ioc.value),
                    "description": f"Search for internal IP activity: {ioc.value}",
                    "ioc_value": ioc.value,
                })
            elif ioc.type == IOCType.USERNAME:
                index_desc = "Okta (system_audit)" if self._is_internal_user(ioc.value) else "Auth0"
                queries.append({
                    "query": self.build_user_query(ioc.value),
                    "description": f"Search for user activity in {index_desc}: {ioc.value}",
                    "ioc_value": ioc.value,
                })
            elif ioc.type == IOCType.EMAIL:
                email_iocs.append(ioc.value)
                index_desc = "Okta (system_audit)" if self._is_internal_user(ioc.value) else "Auth0"
                queries.append({
                    "query": self.build_email_query(ioc.value),
                    "description": f"Search for email activity in {index_desc}: {ioc.value}",
                    "ioc_value": ioc.value,
                })
            elif ioc.type == IOCType.HOSTNAME:
                queries.append({
                    "query": self.build_host_query(ioc.value),
                    "description": f"Search for host activity: {ioc.value}",
                    "ioc_value": ioc.value,
                })
            elif ioc.is_hash:
                queries.append({
                    "query": self.build_hash_query(ioc.value, ioc.hash_type or "sha256"),
                    "description": f"Search for file hash: {ioc.value}",
                    "ioc_value": ioc.value,
                })

        # Add device fingerprint analysis queries for authentication-related alerts
        if include_fingerprint_analysis and email_iocs:
            queries.extend(self._get_fingerprint_queries(email_iocs, ip_iocs, alert_type))

        return queries

    def _get_fingerprint_queries(
        self,
        email_iocs: List[str],
        ip_iocs: List[str],
        alert_type: str = None,
    ) -> List[Dict[str, str]]:
        """
        Generate device fingerprint analysis queries for authentication investigations.

        These queries are critical for:
        - Impossible Travel alerts: Determine if logins from different locations are same device
        - Account Compromise alerts: Identify new/unknown devices accessing the account

        Args:
            email_iocs: List of email addresses to analyze
            ip_iocs: List of IP addresses involved in the alert
            alert_type: Type of alert for query prioritization

        Returns:
            List of fingerprint analysis queries
        """
        queries = []

        for email in email_iocs:
            # Skip internal users for now (they use Okta which has different fingerprint fields)
            if self._is_internal_user(email):
                continue

            # 1. COMPREHENSIVE device fingerprint analysis (90 days) - PRIMARY QUERY
            # This single query provides complete device fingerprint context per IP
            queries.append({
                "query": self.build_comprehensive_device_fingerprint_query(email, "-90d"),
                "description": f"[FINGERPRINT] Comprehensive device fingerprint analysis for {email} (90 days)",
                "ioc_value": email,
                "analysis_type": "comprehensive_fingerprint",
                "earliest_time": "-90d",
                "latest_time": "now",
            })

            # 2. Auth0 risk assessment history
            queries.append({
                "query": self.build_auth0_risk_assessment_query(email),
                "description": f"[FINGERPRINT] Auth0 risk assessments for {email}",
                "ioc_value": email,
                "analysis_type": "risk_assessment",
            })

            # 3. For impossible travel: Compare fingerprints between suspicious IPs
            if len(ip_iocs) >= 2:
                queries.append({
                    "query": self.build_impossible_travel_fingerprint_query(email, ip_iocs[0], ip_iocs[1]),
                    "description": f"[FINGERPRINT] Compare devices between {ip_iocs[0]} and {ip_iocs[1]}",
                    "ioc_value": email,
                    "analysis_type": "impossible_travel_comparison",
                })

        return queries


# Tool definitions for Claude
SPLUNK_TOOLS = [
    {
        "name": "splunk_search",
        "description": "Execute a Splunk SPL query to search for security events. Use this to investigate IOCs, find related activity, and build timelines.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "The SPL query to execute. Should include index specification and search terms.",
                },
                "earliest_time": {
                    "type": "string",
                    "description": "Start time for search (e.g., '-24h', '-7d', '2024-01-01T00:00:00'). Defaults to -24h.",
                    "default": "-24h",
                },
                "latest_time": {
                    "type": "string",
                    "description": "End time for search (e.g., 'now', '-1h'). Defaults to now.",
                    "default": "now",
                },
                "row_limit": {
                    "type": "integer",
                    "description": "Maximum number of results to return. Defaults to 100.",
                    "default": 100,
                },
            },
            "required": ["query"],
        },
    },
    {
        "name": "splunk_get_indexes",
        "description": "Get list of available Splunk indexes to understand what data sources are available for investigation.",
        "input_schema": {
            "type": "object",
            "properties": {
                "row_limit": {
                    "type": "integer",
                    "description": "Maximum number of indexes to return",
                    "default": 50,
                },
            },
        },
    },
    {
        "name": "splunk_get_metadata",
        "description": "Get metadata about hosts, sources, or sourcetypes in Splunk to understand what data is available.",
        "input_schema": {
            "type": "object",
            "properties": {
                "metadata_type": {
                    "type": "string",
                    "enum": ["hosts", "sources", "sourcetypes"],
                    "description": "Type of metadata to retrieve",
                },
                "index": {
                    "type": "string",
                    "description": "Index to get metadata for. Use '*' for all indexes.",
                    "default": "*",
                },
            },
            "required": ["metadata_type"],
        },
    },
]
