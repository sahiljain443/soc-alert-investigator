"""IOC extraction utilities."""

import re
from typing import List, Optional, Set
from models.ioc import IOC, IOCType


class IOCExtractor:
    """Extract Indicators of Compromise from text."""

    # Regex patterns for different IOC types
    PATTERNS = {
        IOCType.IP_ADDRESS: re.compile(
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
            r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        ),
        IOCType.FILE_HASH_MD5: re.compile(r"\b[a-fA-F0-9]{32}\b"),
        IOCType.FILE_HASH_SHA1: re.compile(r"\b[a-fA-F0-9]{40}\b"),
        IOCType.FILE_HASH_SHA256: re.compile(r"\b[a-fA-F0-9]{64}\b"),
        IOCType.EMAIL: re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"),
        IOCType.DOMAIN: re.compile(
            r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
            r"(?:com|net|org|edu|gov|mil|io|co|uk|de|fr|jp|cn|ru|br|in|au|info|biz|xyz|top)\b",
            re.IGNORECASE,
        ),
        IOCType.URL: re.compile(
            r"https?://[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
            r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*"
            r"(?::\d{1,5})?(?:/[^\s]*)?"
        ),
        IOCType.CVE: re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    }

    # Private IP ranges to identify internal IPs
    PRIVATE_IP_PATTERNS = [
        re.compile(r"^10\."),
        re.compile(r"^172\.(1[6-9]|2[0-9]|3[0-1])\."),
        re.compile(r"^192\.168\."),
        re.compile(r"^127\."),
        re.compile(r"^0\."),
    ]

    # Common internal/system domains to filter
    INTERNAL_DOMAINS = {
        "localhost",
        "local",
        "internal",
        "corp",
        "lan",
    }

    @classmethod
    def extract(cls, text: str, include_internal: bool = True) -> List[IOC]:
        """
        Extract IOCs from text.

        Args:
            text: Text to extract IOCs from
            include_internal: Whether to include internal/private IOCs

        Returns:
            List of unique IOCs found
        """
        iocs: Set[IOC] = set()

        for ioc_type, pattern in cls.PATTERNS.items():
            for match in pattern.finditer(text):
                value = match.group()

                # Get context (surrounding text)
                start = max(0, match.start() - 30)
                end = min(len(text), match.end() + 30)
                context = text[start:end].strip()

                # Check if internal
                is_internal = cls._is_internal(ioc_type, value)

                if not include_internal and is_internal:
                    continue

                ioc = IOC(
                    type=ioc_type,
                    value=value,
                    context=context,
                    is_internal=is_internal,
                )
                iocs.add(ioc)

        return list(iocs)

    @classmethod
    def _is_internal(cls, ioc_type: IOCType, value: str) -> bool:
        """Check if an IOC appears to be internal."""
        if ioc_type == IOCType.IP_ADDRESS:
            for pattern in cls.PRIVATE_IP_PATTERNS:
                if pattern.match(value):
                    return True

        elif ioc_type == IOCType.DOMAIN:
            value_lower = value.lower()
            # Check if domain ends with internal TLD
            for internal in cls.INTERNAL_DOMAINS:
                if value_lower.endswith(f".{internal}") or value_lower == internal:
                    return True

        elif ioc_type == IOCType.EMAIL:
            domain = value.split("@")[-1].lower()
            for internal in cls.INTERNAL_DOMAINS:
                if domain.endswith(f".{internal}") or domain == internal:
                    return True

        return False

    @classmethod
    def extract_hostnames(cls, text: str, known_patterns: Optional[List[str]] = None) -> List[IOC]:
        """
        Extract hostnames from text using optional patterns.

        Args:
            text: Text to extract hostnames from
            known_patterns: Optional list of regex patterns for known hostname formats

        Returns:
            List of hostname IOCs
        """
        iocs: Set[IOC] = set()

        # Default patterns for common hostname formats
        default_patterns = [
            r"\b[a-zA-Z][a-zA-Z0-9-]*(?:\d{2,})[a-zA-Z0-9-]*\b",  # host with numbers
            r"\b(?:srv|server|host|node|vm|k8s|pod)-[a-zA-Z0-9-]+\b",  # common prefixes
        ]

        patterns = known_patterns or default_patterns

        for pattern_str in patterns:
            pattern = re.compile(pattern_str, re.IGNORECASE)
            for match in pattern.finditer(text):
                value = match.group()

                # Skip if it looks like a hash or common word
                if len(value) in (32, 40, 64) and re.match(r"^[a-fA-F0-9]+$", value):
                    continue

                start = max(0, match.start() - 30)
                end = min(len(text), match.end() + 30)
                context = text[start:end].strip()

                ioc = IOC(
                    type=IOCType.HOSTNAME,
                    value=value,
                    context=context,
                    is_internal=True,  # Hostnames are typically internal
                )
                iocs.add(ioc)

        return list(iocs)

    @classmethod
    def extract_usernames(cls, text: str, username_patterns: Optional[List[str]] = None) -> List[IOC]:
        """
        Extract usernames from text.

        Args:
            text: Text to extract usernames from
            username_patterns: Optional regex patterns for username formats

        Returns:
            List of username IOCs
        """
        iocs: Set[IOC] = set()

        # Look for common username patterns in context
        context_patterns = [
            r"user[=:\s]+([a-zA-Z0-9._-]+)",
            r"username[=:\s]+([a-zA-Z0-9._-]+)",
            r"account[=:\s]+([a-zA-Z0-9._-]+)",
            r"login[=:\s]+([a-zA-Z0-9._-]+)",
        ]

        for pattern_str in context_patterns:
            pattern = re.compile(pattern_str, re.IGNORECASE)
            for match in pattern.finditer(text):
                value = match.group(1)

                # Skip if too short or looks like a common word
                if len(value) < 3 or value.lower() in {"the", "and", "for", "not", "with"}:
                    continue

                start = max(0, match.start() - 30)
                end = min(len(text), match.end() + 30)
                context = text[start:end].strip()

                ioc = IOC(
                    type=IOCType.USERNAME,
                    value=value,
                    context=context,
                    is_internal=True,
                )
                iocs.add(ioc)

        return list(iocs)
