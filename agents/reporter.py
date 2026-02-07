"""Reporter - Tier 3: Generates investigation reports."""

import re
from typing import Any, Dict, List, Optional, Tuple

from models.alert import DataDogAlert
from models.ioc import IOC, IOCType
from models.finding import Finding, RiskLevel, FindingSource
from utils.alert_classifier import is_account_takeover_alert
from utils.investigation_presenter import (
    InvestigationPresenter, Verdict, Severity,
    Evidence, Recommendation, DeviceFingerprint, TimelineEvent,
)


class Reporter:
    """
    Tier 3 Reporter.

    Consolidates investigation findings and generates reports.
    """

    def __init__(self, presenter: Optional[InvestigationPresenter] = None):
        """Initialize the Reporter."""
        self.presenter = presenter or InvestigationPresenter(use_emojis=True)

    def _is_account_takeover_alert(self, alert: DataDogAlert) -> bool:
        """Check if the alert is related to account takeover."""
        return is_account_takeover_alert(alert.title, alert.message)

    def _format_ip_threat_intel_table(
        self,
        alert: DataDogAlert,
        findings: List[Finding],
    ) -> List[Dict[str, Any]]:
        """
        Format IP threat intelligence findings as a structured table for Key Findings.

        This method extracts and formats IP-related threat intel from both the alert
        and investigation findings into a standardized table format.

        Returns:
            List of dicts with keys: ip, location, reputation, blocklists, known_activity, risk_level
        """
        ip_table = []
        processed_ips = set()

        # Extract IPs from alert network data
        network_data = alert.attributes.get("network", {})
        client_data = network_data.get("client", {})
        alert_ips = client_data.get("ip", [])
        if isinstance(alert_ips, str):
            alert_ips = [alert_ips]

        # Get geoip data for location mapping
        geoip_data = client_data.get("geoip", {})
        cities = geoip_data.get("city", {}).get("name", [])
        countries = geoip_data.get("country", {}).get("name", [])
        as_data = geoip_data.get("as", {})
        isp_names = as_data.get("name", [])

        if isinstance(cities, str):
            cities = [cities]
        if isinstance(countries, str):
            countries = [countries]
        if isinstance(isp_names, str):
            isp_names = [isp_names]

        # Also check IP list in network.ip.list
        ip_list = network_data.get("ip", {}).get("list", [])
        if isinstance(ip_list, str):
            ip_list = [ip_list]

        all_alert_ips = list(set(alert_ips + ip_list))

        # Build location mapping from alert data
        ip_locations = {}
        for i, ip in enumerate(alert_ips):
            location_parts = []
            if i < len(cities) and cities[i]:
                location_parts.append(cities[i])
            if i < len(countries) and countries[i]:
                location_parts.append(countries[i])
            ip_locations[ip] = ", ".join(location_parts) if location_parts else "Unknown"

        # Extract threat intel from findings (AbuseIPDB, VirusTotal)
        ip_findings = {}
        for finding in findings:
            if finding.source in (FindingSource.ABUSEIPDB, FindingSource.VIRUSTOTAL, FindingSource.THREAT_INTEL):
                if finding.ioc_value and self._is_ip_address(finding.ioc_value):
                    if finding.ioc_value not in ip_findings:
                        ip_findings[finding.ioc_value] = {
                            "reputation": [],
                            "blocklists": [],
                            "known_activity": [],
                            "risk_level": finding.risk_level.value,
                        }

                    # Parse finding details
                    if "malicious" in finding.description.lower():
                        ip_findings[finding.ioc_value]["reputation"].append("Malicious")
                    elif "suspicious" in finding.description.lower():
                        ip_findings[finding.ioc_value]["reputation"].append("Suspicious")
                    elif "clean" in finding.description.lower():
                        ip_findings[finding.ioc_value]["reputation"].append("Clean")

                    # Extract blocklist info
                    if "blocklist" in finding.description.lower() or "blacklist" in finding.description.lower():
                        ip_findings[finding.ioc_value]["blocklists"].append(finding.source.value)

                    # Extract known activity
                    if finding.title:
                        ip_findings[finding.ioc_value]["known_activity"].append(finding.title)

                    # Update risk level to highest
                    current_risk = ip_findings[finding.ioc_value]["risk_level"]
                    if self._risk_level_priority(finding.risk_level.value) > self._risk_level_priority(current_risk):
                        ip_findings[finding.ioc_value]["risk_level"] = finding.risk_level.value

        # Extract from alert's embedded threat_intel
        alert_threat_intel = alert.attributes.get("threat_intel", {})
        if alert_threat_intel:
            results = alert_threat_intel.get("results", [])
            for result in results:
                indicator = result.get("indicator", "")
                if indicator and self._is_ip_address(indicator):
                    if indicator not in ip_findings:
                        ip_findings[indicator] = {
                            "reputation": [],
                            "blocklists": [],
                            "known_activity": [],
                            "risk_level": "medium",
                        }

                    category = result.get("category", "")
                    intention = result.get("intention", "")
                    source_name = result.get("source", {}).get("name", "")

                    if category:
                        ip_findings[indicator]["known_activity"].append(category.replace("_", " ").title())
                    if intention:
                        ip_findings[indicator]["reputation"].append(intention.title())
                    if source_name:
                        ip_findings[indicator]["blocklists"].append(source_name)

        # Build the table entries
        for ip in all_alert_ips:
            if ip in processed_ips or not ip:
                continue
            processed_ips.add(ip)

            finding_data = ip_findings.get(ip, {})
            reputation_list = finding_data.get("reputation", [])
            blocklists = finding_data.get("blocklists", [])
            known_activity = finding_data.get("known_activity", [])
            risk_level = finding_data.get("risk_level", "info")

            # Determine reputation summary
            if reputation_list:
                reputation = ", ".join(set(reputation_list))
            elif blocklists:
                reputation = "Flagged"
            else:
                reputation = "Unknown"

            ip_table.append({
                "ip": ip,
                "location": ip_locations.get(ip, "Unknown"),
                "reputation": reputation,
                "blocklists": "Yes" if blocklists else "No",
                "blocklist_sources": list(set(blocklists)),
                "known_activity": "; ".join(set(known_activity)) if known_activity else "None identified",
                "risk_level": risk_level,
            })

        return ip_table

    def _is_ip_address(self, value: str) -> bool:
        """Check if a string is an IP address (IPv4 or IPv6)."""
        import re
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:)*::([0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}$'
        return bool(re.match(ipv4_pattern, value) or re.match(ipv6_pattern, value))

    def _risk_level_priority(self, risk_level: str) -> int:
        """Return priority value for risk level comparison."""
        priorities = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1,
        }
        return priorities.get(risk_level.lower(), 0)

    # --- Presenter mapping methods ---

    _RISK_TO_SEVERITY = {
        RiskLevel.CRITICAL: Severity.CRITICAL,
        RiskLevel.HIGH: Severity.HIGH,
        RiskLevel.MEDIUM: Severity.MEDIUM,
        RiskLevel.LOW: Severity.LOW,
        RiskLevel.INFO: Severity.INFO,
    }

    def _map_risk_level_to_severity(self, risk_level: RiskLevel) -> Severity:
        """Map RiskLevel enum to the presenter's Severity enum."""
        return self._RISK_TO_SEVERITY.get(risk_level, Severity.INFO)

    def _determine_verdict(
        self,
        risk_assessment: Dict[str, Any],
        findings: List[Finding],
    ) -> Tuple[Verdict, str]:
        """Derive verdict and confidence from risk level and finding counts."""
        risk_level = risk_assessment["level"]

        critical_count = sum(1 for f in findings if f.risk_level == RiskLevel.CRITICAL)
        high_count = sum(1 for f in findings if f.risk_level == RiskLevel.HIGH)
        medium_count = sum(1 for f in findings if f.risk_level == RiskLevel.MEDIUM)

        if risk_level == RiskLevel.CRITICAL or critical_count >= 2:
            return Verdict.MALICIOUS, "HIGH"
        elif risk_level == RiskLevel.HIGH or (critical_count >= 1 and high_count >= 1):
            return Verdict.SUSPICIOUS, "HIGH"
        elif risk_level == RiskLevel.MEDIUM:
            return Verdict.SUSPICIOUS, "MEDIUM"
        elif risk_level == RiskLevel.LOW and (medium_count > 0 or high_count > 0):
            return Verdict.INCONCLUSIVE, "LOW"
        elif risk_level == RiskLevel.LOW:
            return Verdict.BENIGN, "MEDIUM"
        else:
            return Verdict.BENIGN, "LOW"

    def _build_presenter_data(
        self,
        report: Dict[str, Any],
        alert: DataDogAlert,
        iocs: List[IOC],
        findings: List[Finding],
    ) -> Dict[str, Any]:
        """Map report data to InvestigationPresenter.print_full_report() kwargs."""
        risk_assessment = {
            "level": RiskLevel(report["overall_risk_level"]),
            "score": report["risk_score"],
            "factors": report["risk_factors"],
        }

        # --- source_ips ---
        network_data = alert.attributes.get("network", {})
        client_data = network_data.get("client", {})
        alert_ips = client_data.get("ip", [])
        if isinstance(alert_ips, str):
            alert_ips = [alert_ips]
        ip_list = network_data.get("ip", {}).get("list", [])
        if isinstance(ip_list, str):
            ip_list = [ip_list]
        source_ips = list(dict.fromkeys(alert_ips + ip_list))  # dedupe, preserve order
        if not source_ips:
            source_ips = [ioc.value for ioc in iocs if ioc.is_ip and not ioc.is_internal]

        # --- target_user ---
        target_user = (
            alert.attributes.get("usr", {}).get("email")
            or alert.attributes.get("target_user")
        )

        # --- evidence_list ---
        evidence_list = []
        for f in findings:
            if f.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM):
                evidence_list.append(Evidence(
                    description=f.title,
                    source=f.source.value,
                    severity=self._map_risk_level_to_severity(f.risk_level),
                    data={"ioc": f.ioc_value} if f.ioc_value else None,
                ))

        # --- recommendations ---
        priority_map = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        recommendations = []
        for i, rec_str in enumerate(report.get("recommendations", [])):
            priority = priority_map[min(i, len(priority_map) - 1)]
            recommendations.append(Recommendation(
                action=rec_str,
                priority=priority,
            ))

        # --- risk_factors ---
        risk_factors = []
        for factor_str in report.get("risk_factors", []):
            # Format is "source: title"
            if ": " in factor_str:
                source_part, title_part = factor_str.split(": ", 1)
                risk_factors.append({
                    "name": title_part,
                    "assessment": f"Identified by {source_part}",
                    "status": "warning",
                    "status_text": "FLAGGED",
                })
            else:
                risk_factors.append({
                    "name": factor_str,
                    "assessment": "Risk factor identified",
                    "status": "warning",
                    "status_text": "FLAGGED",
                })

        # --- iocs ---
        ioc_type_display = {
            IOCType.IP_ADDRESS: "IP Addresses",
            IOCType.DOMAIN: "Domains",
            IOCType.URL: "URLs",
            IOCType.EMAIL: "Emails",
            IOCType.FILE_HASH_MD5: "Hashes",
            IOCType.FILE_HASH_SHA1: "Hashes",
            IOCType.FILE_HASH_SHA256: "Hashes",
            IOCType.HOSTNAME: "Hostnames",
            IOCType.USERNAME: "Usernames",
            IOCType.CVE: "CVEs",
        }
        ioc_grouped: Dict[str, List[str]] = {}
        for ioc in iocs:
            display_name = ioc_type_display.get(ioc.type, ioc.type.value)
            ioc_grouped.setdefault(display_name, []).append(ioc.value)

        # --- verdict ---
        verdict, verdict_confidence = self._determine_verdict(risk_assessment, findings)

        # --- verdict_summary ---
        verdict_summary = report.get("investigation_summary", "")

        # --- fingerprints ---
        fingerprints = []
        if report.get("is_account_takeover") and report.get("device_fingerprint_analysis"):
            dfa = report["device_fingerprint_analysis"]
            for anomaly in dfa.get("anomalies", []):
                fingerprints.append(DeviceFingerprint(
                    ip=anomaly.get("user_agent", "-")[:20] if anomaly.get("type") == "outdated_browser" else "-",
                    device_type=anomaly.get("type", "unknown").replace("_", " ").title(),
                    status=anomaly.get("severity", "unknown"),
                    event_count=0,
                ))

        # --- key_finding ---
        key_finding = None
        if report.get("is_account_takeover"):
            threat_intel = report.get("threat_intel_analysis", {})
            summary = threat_intel.get("summary", "")
            if summary and summary != "No significant threat intel findings":
                finding_items = [summary]
                for geo_info in ([threat_intel.get("geolocation", {})] if isinstance(threat_intel.get("geolocation"), dict) else []):
                    if geo_info.get("anomaly_detected"):
                        finding_items.append(geo_info.get("description", ""))
                for proxy in threat_intel.get("proxy_detection", [])[:3]:
                    finding_items.append(f"Proxy detected: {proxy.get('indicator', '')} ({proxy.get('category', '')})")
                key_finding = {
                    "title": "Threat Intelligence Analysis",
                    "findings": [f for f in finding_items if f],
                    "type": "warning",
                }

        # --- ip_threat_intel ---
        ip_threat_intel = report.get("ip_threat_intel_table")

        # --- findings_by_source ---
        findings_by_source = report.get("findings_by_source")

        return {
            "alert_id": alert.id,
            "title": alert.title,
            "severity": alert.severity,
            "source_ips": source_ips,
            "target_user": target_user,
            "timeline": self._extract_timeline_events(findings),
            "fingerprints": fingerprints,
            "risk_factors": risk_factors,
            "verdict": verdict,
            "verdict_confidence": verdict_confidence,
            "verdict_summary": verdict_summary,
            "evidence_list": evidence_list,
            "recommendations": recommendations,
            "iocs": ioc_grouped if ioc_grouped else None,
            "key_finding": key_finding,
            "ip_threat_intel": ip_threat_intel if ip_threat_intel else None,
            "findings_by_source": findings_by_source if findings_by_source else None,
        }

    def _extract_threat_intel_findings(
        self,
        alert: DataDogAlert,
        findings: List[Finding],
    ) -> Dict[str, Any]:
        """
        Extract threat intelligence findings for account takeover investigations.

        Includes: IP reputation, proxy detection, geolocation anomalies, known threat indicators.
        """
        threat_intel = {
            "ip_reputation": [],
            "proxy_detection": [],
            "geolocation": [],
            "threat_indicators": [],
            "ip_threat_intel_table": [],  # NEW: Structured IP threat intel table
            "summary": "",
        }

        # Extract from alert attributes (threat_intel section)
        alert_threat_intel = alert.attributes.get("threat_intel", {})
        if alert_threat_intel:
            results = alert_threat_intel.get("results", [])
            for result in results:
                indicator = {
                    "indicator": result.get("indicator", ""),
                    "type": result.get("type", ""),
                    "category": result.get("category", ""),
                    "intention": result.get("intention", ""),
                    "source": result.get("source", {}).get("name", ""),
                }

                if result.get("category") in ["residential_proxy", "datacenter_proxy", "vpn", "tor"]:
                    threat_intel["proxy_detection"].append(indicator)
                else:
                    threat_intel["threat_indicators"].append(indicator)

        # Extract from findings (AbuseIPDB, VirusTotal, etc.)
        for finding in findings:
            if finding.source in (FindingSource.ABUSEIPDB, FindingSource.VIRUSTOTAL, FindingSource.THREAT_INTEL):
                threat_intel["ip_reputation"].append({
                    "ioc": finding.ioc_value,
                    "title": finding.title,
                    "risk_level": finding.risk_level.value,
                    "description": finding.description,
                    "confidence": finding.confidence,
                })

        # Extract geolocation from alert network data
        network_data = alert.attributes.get("network", {})
        geoip_data = network_data.get("client", {}).get("geoip", {})
        if geoip_data:
            cities = geoip_data.get("city", {}).get("name", [])
            countries = geoip_data.get("country", {}).get("name", [])
            subdivisions = geoip_data.get("subdivision", {}).get("name", [])

            if isinstance(cities, list) and len(cities) > 1:
                threat_intel["geolocation"] = {
                    "cities": cities,
                    "countries": countries if isinstance(countries, list) else [countries],
                    "subdivisions": subdivisions if isinstance(subdivisions, list) else [subdivisions],
                    "anomaly_detected": True,
                    "description": f"Multiple locations detected: {', '.join(cities)}"
                }

        # Generate summary
        proxy_count = len(threat_intel["proxy_detection"])
        malicious_ips = sum(1 for ip in threat_intel["ip_reputation"] if ip["risk_level"] in ["critical", "high"])

        summary_parts = []
        if proxy_count > 0:
            summary_parts.append(f"{proxy_count} residential/anonymous proxy IPs detected")
        if malicious_ips > 0:
            summary_parts.append(f"{malicious_ips} IPs flagged as malicious")
        if threat_intel["geolocation"]:
            summary_parts.append("Geographic anomalies detected")

        threat_intel["summary"] = "; ".join(summary_parts) if summary_parts else "No significant threat intel findings"

        return threat_intel

    def _extract_device_fingerprint_findings(
        self,
        alert: DataDogAlert,
        findings: List[Finding],
    ) -> Dict[str, Any]:
        """
        Extract device fingerprint analysis for account takeover investigations.

        Includes: User agent analysis, device changes, browser anomalies, platform mismatches.
        """
        device_fingerprint = {
            "user_agents": [],
            "devices": [],
            "browsers": [],
            "operating_systems": [],
            "anomalies": [],
            "summary": "",
        }

        # Extract from alert HTTP data
        http_data = alert.attributes.get("http", {})
        user_agents = http_data.get("useragent", [])
        ua_details = http_data.get("useragent_details", {})

        if isinstance(user_agents, list):
            device_fingerprint["user_agents"] = user_agents
        elif isinstance(user_agents, str):
            device_fingerprint["user_agents"] = [user_agents]

        # Extract parsed UA details
        if ua_details:
            os_families = ua_details.get("os", {}).get("family", [])
            browser_families = ua_details.get("browser", {}).get("family", [])
            device_families = ua_details.get("device", {}).get("family", [])

            device_fingerprint["operating_systems"] = os_families if isinstance(os_families, list) else [os_families]
            device_fingerprint["browsers"] = browser_families if isinstance(browser_families, list) else [browser_families]
            device_fingerprint["devices"] = device_families if isinstance(device_families, list) else [device_families]

        # Detect anomalies
        anomalies = []

        # Check for multiple device types
        if len(set(device_fingerprint["devices"])) > 1:
            anomalies.append({
                "type": "multiple_devices",
                "severity": "high",
                "description": f"Multiple device types detected: {', '.join(set(device_fingerprint['devices']))}",
            })

        # Check for multiple OS families
        if len(set(device_fingerprint["operating_systems"])) > 1:
            anomalies.append({
                "type": "multiple_os",
                "severity": "high",
                "description": f"Multiple operating systems detected: {', '.join(set(device_fingerprint['operating_systems']))}",
            })

        # Check for outdated browser versions
        for ua in device_fingerprint["user_agents"]:
            chrome_match = re.search(r"Chrome/(\d+)", ua)
            if chrome_match:
                chrome_version = int(chrome_match.group(1))
                # Chrome versions below 100 are significantly outdated
                if chrome_version < 100:
                    anomalies.append({
                        "type": "outdated_browser",
                        "severity": "medium",
                        "description": f"Outdated Chrome version {chrome_version} detected (current is 120+). May indicate automated tooling.",
                        "user_agent": ua,
                    })

        # Check for desktop/mobile mismatch with impossible travel
        has_desktop = any("Mac" in d or "Windows" in d for d in device_fingerprint["devices"])
        has_mobile = any("Android" in d or "iPhone" in d or d == "K" for d in device_fingerprint["devices"])
        if has_desktop and has_mobile:
            anomalies.append({
                "type": "platform_mismatch",
                "severity": "high",
                "description": "Both desktop and mobile devices detected during impossible travel event",
            })

        device_fingerprint["anomalies"] = anomalies

        # Extract from device fingerprint findings
        for finding in findings:
            if finding.source == FindingSource.DEVICE_FINGERPRINT:
                device_fingerprint["anomalies"].append({
                    "type": "finding",
                    "severity": finding.risk_level.value,
                    "description": finding.description,
                })

        # Generate summary
        anomaly_count = len(anomalies)
        ua_count = len(device_fingerprint["user_agents"])

        summary_parts = []
        if ua_count > 1:
            summary_parts.append(f"{ua_count} distinct user agents detected")
        if anomaly_count > 0:
            high_severity = sum(1 for a in anomalies if a["severity"] == "high")
            summary_parts.append(f"{anomaly_count} device anomalies detected ({high_severity} high severity)")

        device_fingerprint["summary"] = "; ".join(summary_parts) if summary_parts else "No device fingerprint anomalies"

        return device_fingerprint

    def _deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """Remove duplicate findings, keeping the highest-risk instance.

        Findings are grouped by ``(source, ioc_value)``; within each group
        the finding with the highest risk level (then highest confidence) is
        kept.
        """
        risk_order = {
            RiskLevel.CRITICAL: 5,
            RiskLevel.HIGH: 4,
            RiskLevel.MEDIUM: 3,
            RiskLevel.LOW: 2,
            RiskLevel.INFO: 1,
        }

        best: Dict[Tuple[str, Optional[str]], Finding] = {}
        for f in findings:
            key = (f.source.value, f.ioc_value)
            existing = best.get(key)
            if existing is None:
                best[key] = f
            else:
                e_rank = (risk_order.get(existing.risk_level, 0), existing.confidence)
                f_rank = (risk_order.get(f.risk_level, 0), f.confidence)
                if f_rank > e_rank:
                    best[key] = f
        return list(best.values())

    def _extract_timeline_events(self, findings: List[Finding]) -> List[TimelineEvent]:
        """Parse Splunk timeline query results into TimelineEvent objects."""
        events: List[TimelineEvent] = []

        for finding in findings:
            if finding.source != FindingSource.SPLUNK:
                continue
            raw = finding.raw_data
            if not isinstance(raw, dict):
                continue
            data = raw.get("data", [])
            if not isinstance(data, list):
                continue
            for row in data:
                if not isinstance(row, dict):
                    continue
                ts = row.get("_time")
                if not ts:
                    continue
                action = row.get("action", row.get("status", "event"))
                desc_parts = []
                if row.get("sourcetype"):
                    desc_parts.append(row["sourcetype"])
                if row.get("user"):
                    desc_parts.append(f"user={row['user']}")
                if row.get("host"):
                    desc_parts.append(f"host={row['host']}")
                description = " | ".join(desc_parts) if desc_parts else finding.title
                ip = row.get("src_ip") or row.get("dest_ip")

                status = "info"
                action_lower = str(action).lower()
                if "fail" in action_lower or "denied" in action_lower:
                    status = "failed"
                elif "success" in action_lower or "allow" in action_lower:
                    status = "success"

                events.append(TimelineEvent(
                    timestamp=str(ts),
                    event_type=str(action),
                    description=description,
                    ip=str(ip) if ip else None,
                    status=status,
                ))
        return events

    def generate_report(
        self,
        alert: DataDogAlert,
        iocs: List[IOC],
        findings: List[Finding],
    ) -> Dict[str, Any]:
        """
        Generate a comprehensive investigation report.

        Args:
            alert: The original alert
            iocs: Extracted IOCs
            findings: All investigation findings

        Returns:
            Report data including risk assessment and recommendations
        """
        # Deduplicate findings before scoring
        findings = self._deduplicate_findings(findings)

        # Calculate risk assessment
        risk_assessment = self._calculate_risk(alert, findings)

        # Generate recommendations
        recommendations = self._generate_recommendations(alert, findings, risk_assessment)

        # Generate summary
        summary = self._generate_summary(alert, iocs, findings, risk_assessment)

        # Build the report
        report = {
            "alert_id": alert.id,
            "alert_title": alert.title,
            "alert_severity": alert.severity,
            "investigation_summary": summary,
            "ioc_count": len(iocs),
            "iocs": [{"type": ioc.type.value, "value": ioc.value, "internal": ioc.is_internal} for ioc in iocs],
            "finding_count": len(findings),
            "findings_by_source": self._group_findings_by_source(findings),
            "overall_risk_level": risk_assessment["level"].value,
            "risk_score": risk_assessment["score"],
            "risk_factors": risk_assessment["factors"],
            "recommendations": recommendations,
        }

        # Add account takeover specific sections
        if self._is_account_takeover_alert(alert):
            report["is_account_takeover"] = True
            report["threat_intel_analysis"] = self._extract_threat_intel_findings(alert, findings)
            report["device_fingerprint_analysis"] = self._extract_device_fingerprint_findings(alert, findings)

            # Update recommendations for ATO alerts
            ato_recommendations = self._generate_ato_recommendations(
                report["threat_intel_analysis"],
                report["device_fingerprint_analysis"],
            )
            report["recommendations"] = ato_recommendations + report["recommendations"]
        else:
            report["is_account_takeover"] = False

        # Add IP threat intel table (always computed, used by presenter)
        report["ip_threat_intel_table"] = self._format_ip_threat_intel_table(alert, findings)

        # Print Rich-formatted report
        presenter_data = self._build_presenter_data(report, alert, iocs, findings)
        self.presenter.print_full_report(**presenter_data)

        return report

    def _calculate_risk(self, alert: DataDogAlert, findings: List[Finding]) -> Dict[str, Any]:
        """Calculate overall risk assessment from findings."""
        severity_scores = {
            "critical": 0.9,
            "high": 0.7,
            "medium": 0.5,
            "low": 0.3,
        }
        base_score = severity_scores.get(alert.severity, 0.5)

        risk_factors = []
        finding_scores = []

        for finding in findings:
            finding_risk_score = {
                RiskLevel.CRITICAL: 1.0,
                RiskLevel.HIGH: 0.8,
                RiskLevel.MEDIUM: 0.5,
                RiskLevel.LOW: 0.2,
                RiskLevel.INFO: 0.0,
            }.get(finding.risk_level, 0.0)

            finding_scores.append(finding_risk_score * finding.confidence)

            if finding.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
                risk_factors.append(f"{finding.source.value}: {finding.title}")

        if finding_scores:
            max_score = max(finding_scores)
            avg_score = sum(finding_scores) / len(finding_scores)
            findings_score = max_score * 0.6 + avg_score * 0.4
            final_score = (base_score * 0.3) + (findings_score * 0.7)
        else:
            final_score = base_score * 0.5

        if final_score >= 0.8:
            level = RiskLevel.CRITICAL
        elif final_score >= 0.6:
            level = RiskLevel.HIGH
        elif final_score >= 0.4:
            level = RiskLevel.MEDIUM
        elif final_score >= 0.2:
            level = RiskLevel.LOW
        else:
            level = RiskLevel.INFO

        return {
            "level": level,
            "score": final_score,
            "factors": risk_factors[:5],
        }

    def _generate_recommendations(
        self,
        alert: DataDogAlert,
        findings: List[Finding],
        risk_assessment: Dict[str, Any],
    ) -> List[str]:
        """Generate prioritized recommendations based on findings."""
        recommendations = []
        risk_level = risk_assessment["level"]

        if risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
            recommendations.append("Escalate to incident response team immediately")
            recommendations.append("Isolate affected systems if active threat indicators present")
            recommendations.append("Preserve evidence and initiate forensic analysis")

        has_malicious_ip = False
        has_malicious_hash = False
        has_failed_auth = False

        for finding in findings:
            if finding.source == FindingSource.ABUSEIPDB and finding.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
                has_malicious_ip = True
            if finding.source == FindingSource.VIRUSTOTAL and finding.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
                if finding.ioc_value and len(finding.ioc_value) in (32, 40, 64):
                    has_malicious_hash = True
                else:
                    has_malicious_ip = True
            if "failed" in finding.title.lower() or "denied" in finding.title.lower():
                has_failed_auth = True

        if has_malicious_ip:
            recommendations.append("Block identified malicious IP addresses at firewall/WAF")
            recommendations.append("Review all connections to/from flagged IPs in the past 7 days")

        if has_malicious_hash:
            recommendations.append("Scan all endpoints for identified malicious file hashes")
            recommendations.append("Quarantine and analyze any matching files found")

        if has_failed_auth:
            recommendations.append("Review user accounts involved in failed authentication attempts")
            recommendations.append("Consider implementing additional authentication controls")

        if risk_level == RiskLevel.MEDIUM:
            recommendations.append("Continue monitoring affected systems for 24-48 hours")
            recommendations.append("Review related logs for additional context")

        if risk_level == RiskLevel.LOW:
            recommendations.append("Document findings for future reference")
            recommendations.append("No immediate action required - continue routine monitoring")

        if not recommendations:
            recommendations.append("No significant threats identified")
            recommendations.append("Close alert after documentation")

        return recommendations[:7]

    def _generate_ato_recommendations(
        self,
        threat_intel: Dict[str, Any],
        device_fingerprint: Dict[str, Any],
    ) -> List[str]:
        """Generate recommendations specific to account takeover investigations."""
        recommendations = []

        # Threat intel based recommendations
        if threat_intel["proxy_detection"]:
            proxy_ips = [p["indicator"] for p in threat_intel["proxy_detection"]]
            recommendations.append(f"Block residential proxy IPs: {', '.join(proxy_ips[:5])}")
            recommendations.append("Implement residential proxy detection in authentication flow")

        if any(ip["risk_level"] in ["critical", "high"] for ip in threat_intel["ip_reputation"]):
            recommendations.append("Block identified malicious IPs at WAF/firewall immediately")

        if threat_intel["geolocation"] and threat_intel["geolocation"].get("anomaly_detected"):
            recommendations.append("Review all sessions from anomalous geographic locations")

        # Device fingerprint based recommendations
        high_severity_anomalies = [a for a in device_fingerprint["anomalies"] if a.get("severity") == "high"]

        if any(a["type"] == "outdated_browser" for a in device_fingerprint["anomalies"]):
            recommendations.append("Investigate sessions with outdated browser versions - possible automated attack")

        if any(a["type"] == "platform_mismatch" for a in device_fingerprint["anomalies"]):
            recommendations.append("Device platform mismatch detected - likely different actors using same credentials")

        if any(a["type"] == "multiple_devices" for a in device_fingerprint["anomalies"]):
            recommendations.append("Force re-authentication on all devices for affected account")

        # General ATO recommendations
        if threat_intel["proxy_detection"] or high_severity_anomalies:
            recommendations.insert(0, "IMMEDIATE: Disable affected user account and terminate all active sessions")
            recommendations.append("Force password reset and MFA re-enrollment before re-enabling account")
            recommendations.append("Review account activity for data exfiltration or unauthorized changes")
            recommendations.append("Check for MFA bypass - investigate push notification logs and device enrollments")

        return recommendations

    def _group_findings_by_source(self, findings: List[Finding]) -> Dict[str, List[Dict[str, Any]]]:
        """Group findings by their source."""
        grouped: Dict[str, List[Dict[str, Any]]] = {}

        for finding in findings:
            source = finding.source.value
            if source not in grouped:
                grouped[source] = []

            grouped[source].append({
                "title": finding.title,
                "description": finding.description,
                "risk_level": finding.risk_level.value,
                "ioc_value": finding.ioc_value,
                "confidence": finding.confidence,
            })

        return grouped

    def _generate_summary(
        self,
        alert: DataDogAlert,
        iocs: List[IOC],
        findings: List[Finding],
        risk_assessment: Dict[str, Any],
    ) -> str:
        """Generate an investigation summary."""
        # Count findings by risk level
        risk_counts = {level: 0 for level in RiskLevel}
        for finding in findings:
            risk_counts[finding.risk_level] += 1

        critical_high = risk_counts[RiskLevel.CRITICAL] + risk_counts[RiskLevel.HIGH]

        summary_parts = [
            f"Investigation of alert '{alert.title}' (severity: {alert.severity}).",
            f"Extracted {len(iocs)} IOCs and collected {len(findings)} findings.",
        ]

        if critical_high > 0:
            summary_parts.append(
                f"Found {critical_high} critical/high risk indicators requiring immediate attention."
            )

        summary_parts.append(
            f"Overall risk assessment: {risk_assessment['level'].value.upper()} "
            f"(score: {risk_assessment['score']:.0%})."
        )

        if risk_assessment["factors"]:
            summary_parts.append("Key risk factors: " + "; ".join(risk_assessment["factors"][:3]))

        # Add ATO-specific summary elements
        if self._is_account_takeover_alert(alert):
            threat_intel = self._extract_threat_intel_findings(alert, findings)
            device_fp = self._extract_device_fingerprint_findings(alert, findings)

            if threat_intel["summary"] and threat_intel["summary"] != "No significant threat intel findings":
                summary_parts.append(f"THREAT INTEL: {threat_intel['summary']}.")

            if device_fp["summary"] and device_fp["summary"] != "No device fingerprint anomalies":
                summary_parts.append(f"DEVICE ANALYSIS: {device_fp['summary']}.")

        return " ".join(summary_parts)
