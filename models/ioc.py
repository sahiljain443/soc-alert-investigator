"""Indicator of Compromise (IOC) model."""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class IOCType(str, Enum):
    """Types of Indicators of Compromise."""

    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH_MD5 = "file_hash_md5"
    FILE_HASH_SHA1 = "file_hash_sha1"
    FILE_HASH_SHA256 = "file_hash_sha256"
    EMAIL = "email"
    USERNAME = "username"
    HOSTNAME = "hostname"
    CVE = "cve"


class IOC(BaseModel):
    """Model representing an Indicator of Compromise."""

    type: IOCType = Field(description="Type of IOC")
    value: str = Field(description="The IOC value")
    context: str = Field(default="", description="Context where the IOC was found")
    is_internal: bool = Field(default=False, description="Whether this appears to be internal")

    def __hash__(self) -> int:
        """Make IOC hashable for deduplication."""
        return hash((self.type, self.value.lower()))

    def __eq__(self, other: object) -> bool:
        """Check equality based on type and value."""
        if not isinstance(other, IOC):
            return False
        return self.type == other.type and self.value.lower() == other.value.lower()

    @property
    def is_ip(self) -> bool:
        """Check if this IOC is an IP address."""
        return self.type == IOCType.IP_ADDRESS

    @property
    def is_hash(self) -> bool:
        """Check if this IOC is a file hash."""
        return self.type in (
            IOCType.FILE_HASH_MD5,
            IOCType.FILE_HASH_SHA1,
            IOCType.FILE_HASH_SHA256,
        )

    @property
    def is_domain(self) -> bool:
        """Check if this IOC is a domain."""
        return self.type == IOCType.DOMAIN

    @property
    def hash_type(self) -> Optional[str]:
        """Get the hash type if this is a hash IOC."""
        if self.type == IOCType.FILE_HASH_MD5:
            return "md5"
        elif self.type == IOCType.FILE_HASH_SHA1:
            return "sha1"
        elif self.type == IOCType.FILE_HASH_SHA256:
            return "sha256"
        return None
