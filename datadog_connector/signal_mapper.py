"""Map DataDog security signals to DataDogAlert model."""

from datetime import datetime
from typing import Any, Dict, List, Optional


class SignalMapper:
    """Maps DataDog security signal format to soc-alert-investigator format.

    DataDog security signals have a nested structure that needs to be
    flattened and mapped to the DataDogAlert model fields.
    """

    # Severity mapping from DataDog signal severity values
    # DataDog uses numeric severity: 0=info, 1=low, 2=medium, 3=high, 4=critical
    SEVERITY_MAP = {
        "info": "low",
        "low": "low",
        "medium": "medium",
        "high": "high",
        "critical": "critical",
        # Numeric mappings
        "0": "low",
        "1": "low",
        "2": "medium",
        "3": "high",
        "4": "critical",
        0: "low",
        1: "low",
        2: "medium",
        3: "high",
        4: "critical",
    }

    @classmethod
    def map_signal(cls, signal: Dict[str, Any]) -> Dict[str, Any]:
        """Map a DataDog security signal to DataDogAlert-compatible format.

        Args:
            signal: Raw DataDog security signal from API.

        Returns:
            Dictionary compatible with DataDogAlert.from_raw().
        """
        # Extract nested attributes
        attributes = signal.get("attributes", {})
        signal_attributes = attributes.get("attributes", {})

        # Get the signal ID
        signal_id = signal.get("id", "unknown")

        # Extract title from rule or message
        title = cls._extract_title(attributes)

        # Extract message/description
        message = cls._extract_message(attributes, signal_attributes)

        # Extract severity
        severity = cls._map_severity(attributes.get("severity", "medium"))

        # Extract status
        status = attributes.get("status", "open")

        # Extract timestamp
        timestamp = cls._parse_timestamp(attributes.get("timestamp"))

        # Extract tags
        tags = cls._extract_tags(attributes, signal_attributes)

        # Extract host information
        host = cls._extract_host(signal_attributes)

        # Extract service information
        service = cls._extract_service(signal_attributes)

        # Build flattened attributes dict with all useful signal data
        flat_attributes = cls._build_flat_attributes(attributes, signal_attributes)

        return {
            "id": signal_id,
            "title": title,
            "message": message,
            "severity": severity,
            "status": status,
            "source": "datadog",
            "tags": tags,
            "timestamp": timestamp,
            "host": host,
            "service": service,
            "attributes": flat_attributes,
        }

    @classmethod
    def _extract_title(cls, attributes: Dict[str, Any]) -> str:
        """Extract title from signal attributes."""
        # Check nested attributes first (DataDog Security Signal structure)
        nested_attrs = attributes.get("attributes", {})

        # Title is often in nested attributes
        if "title" in nested_attrs:
            return nested_attrs["title"]

        # Or in workflow.rule.name
        workflow = nested_attrs.get("workflow", {})
        rule = workflow.get("rule", {})
        if isinstance(rule, dict) and "name" in rule:
            return rule["name"]

        # Fallback to top-level title
        if "title" in attributes:
            return attributes["title"]

        # Try rule at top level
        if "rule" in attributes:
            rule = attributes["rule"]
            if isinstance(rule, dict):
                return rule.get("name", "Untitled Signal")
            return str(rule)

        # Use first line of message as title if no explicit title (skip %%% placeholders)
        if "message" in attributes:
            message = attributes["message"]
            if isinstance(message, str) and not message.startswith("%%%"):
                first_line = message.split("\n")[0][:100]
                return first_line if first_line else "Security Signal"

        return "Security Signal"

    @classmethod
    def _extract_message(
        cls, attributes: Dict[str, Any], signal_attributes: Dict[str, Any]
    ) -> str:
        """Extract full message/description from signal."""
        parts = []

        # Add main message
        if "message" in attributes:
            parts.append(str(attributes["message"]))

        # Add description if different from message
        if "description" in attributes and attributes.get("description") != attributes.get("message"):
            parts.append(str(attributes["description"]))

        # Add rule description if available
        rule = attributes.get("rule", {})
        if isinstance(rule, dict) and "description" in rule:
            if rule["description"] not in parts:
                parts.append(rule["description"])

        # Add any custom attributes that might contain useful context
        for key in ["reason", "summary", "details"]:
            if key in signal_attributes:
                value = signal_attributes[key]
                if isinstance(value, str) and value not in parts:
                    parts.append(f"{key}: {value}")

        return "\n\n".join(parts) if parts else ""

    @classmethod
    def _map_severity(cls, severity) -> str:
        """Map DataDog severity to standard severity levels."""
        # Try direct lookup first (handles numeric values)
        if severity in cls.SEVERITY_MAP:
            return cls.SEVERITY_MAP[severity]
        # Fallback to string conversion
        return cls.SEVERITY_MAP.get(str(severity).lower(), "medium")

    @classmethod
    def _parse_timestamp(cls, ts: Any) -> str:
        """Parse timestamp from various formats to ISO string."""
        if ts is None:
            return datetime.utcnow().isoformat() + "Z"

        if isinstance(ts, (int, float)):
            # Unix timestamp (milliseconds or seconds)
            if ts > 1e12:
                ts = ts / 1000
            dt = datetime.utcfromtimestamp(ts)
            return dt.isoformat() + "Z"

        if isinstance(ts, str):
            return ts

        return datetime.utcnow().isoformat() + "Z"

    @classmethod
    def _extract_tags(
        cls, attributes: Dict[str, Any], signal_attributes: Dict[str, Any]
    ) -> List[str]:
        """Extract and combine tags from signal."""
        tags = set()

        # Add explicit tags
        if "tags" in attributes:
            for tag in attributes["tags"]:
                if isinstance(tag, str):
                    tags.add(tag)

        # Add rule tags
        rule = attributes.get("rule", {})
        if isinstance(rule, dict) and "tags" in rule:
            for tag in rule["tags"]:
                if isinstance(tag, str):
                    tags.add(tag)

        # Add type/category as tags
        if "type" in attributes:
            tags.add(f"type:{attributes['type']}")

        # Add severity as tag for filtering
        if "severity" in attributes:
            tags.add(f"severity:{attributes['severity']}")

        return list(tags)

    @classmethod
    def _extract_host(cls, signal_attributes: Dict[str, Any]) -> Optional[str]:
        """Extract host information from signal attributes."""
        # Try various common locations for host info
        for key in ["host", "hostname", "device.hostname", "server"]:
            if key in signal_attributes:
                return str(signal_attributes[key])

        # Check nested structures
        if "host" in signal_attributes and isinstance(signal_attributes["host"], dict):
            return signal_attributes["host"].get("name")

        # Check network attributes
        network = signal_attributes.get("network", {})
        if isinstance(network, dict):
            destination = network.get("destination", {})
            if isinstance(destination, dict) and "hostname" in destination:
                return destination["hostname"]

        return None

    @classmethod
    def _extract_service(cls, signal_attributes: Dict[str, Any]) -> Optional[str]:
        """Extract service information from signal attributes."""
        for key in ["service", "service.name", "application"]:
            if key in signal_attributes:
                return str(signal_attributes[key])
        return None

    @classmethod
    def _build_flat_attributes(
        cls, attributes: Dict[str, Any], signal_attributes: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Build a flattened attributes dictionary with all useful data."""
        flat = {}

        # Include network information (IPs, ports, etc.)
        if "network" in signal_attributes:
            network = signal_attributes["network"]
            if isinstance(network, dict):
                # Extract client IP
                client = network.get("client", {})
                if isinstance(client, dict):
                    if "ip" in client:
                        flat["source_ip"] = client["ip"]
                    if "port" in client:
                        flat["source_port"] = client["port"]

                # Extract destination IP
                destination = network.get("destination", {})
                if isinstance(destination, dict):
                    if "ip" in destination:
                        flat["destination_ip"] = destination["ip"]
                    if "port" in destination:
                        flat["destination_port"] = destination["port"]

        # Include user information
        if "usr" in signal_attributes:
            usr = signal_attributes["usr"]
            if isinstance(usr, dict):
                if "email" in usr:
                    flat["user_email"] = usr["email"]
                if "id" in usr:
                    flat["user_id"] = usr["id"]
                if "name" in usr:
                    flat["user_name"] = usr["name"]

        # Include HTTP information
        if "http" in signal_attributes:
            http = signal_attributes["http"]
            if isinstance(http, dict):
                for key in ["method", "url", "status_code", "useragent"]:
                    if key in http:
                        flat[f"http_{key}"] = http[key]

        # Include any IP arrays
        for key in ["source_ips", "destination_ips", "ips"]:
            if key in signal_attributes:
                flat[key] = signal_attributes[key]

        # Include threat intelligence data if present
        if "threat" in signal_attributes:
            flat["threat"] = signal_attributes["threat"]

        # Include rule information
        rule = attributes.get("rule", {})
        if isinstance(rule, dict):
            flat["rule_id"] = rule.get("id")
            flat["rule_name"] = rule.get("name")
            flat["rule_version"] = rule.get("version")

        # Include detection method
        if "detection_method" in attributes:
            flat["detection_method"] = attributes["detection_method"]

        # Include any remaining useful top-level signal attributes
        for key in ["geo", "device", "browser", "os"]:
            if key in signal_attributes:
                flat[key] = signal_attributes[key]

        return flat

    @classmethod
    def map_signals(cls, signals: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Map multiple DataDog security signals.

        Args:
            signals: List of raw DataDog security signals.

        Returns:
            List of dictionaries compatible with DataDogAlert.from_raw().
        """
        return [cls.map_signal(signal) for signal in signals]
