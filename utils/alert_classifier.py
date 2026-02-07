"""Alert classification utilities."""

from typing import Optional


# Superset of account takeover keywords from all modules.
ACCOUNT_TAKEOVER_KEYWORDS = [
    "impossible travel",
    "account takeover",
    "credential",
    "authentication",
    "login",
    "brute force",
    "password spray",
    "mfa bypass",
    "session hijack",
    "token theft",
    "phishing",
    "ato",
    "unauthorized access",
    "suspicious login",
    "anomalous authentication",
    "credential stuffing",
    "new device",
]


def is_account_takeover_alert(title: Optional[str], message: Optional[str]) -> bool:
    """Check if an alert is related to account takeover.

    Args:
        title: Alert title.
        message: Alert message body.

    Returns:
        True if any account-takeover keyword appears in the combined text.
    """
    searchable = f"{title or ''} {message or ''}".lower()
    return any(keyword in searchable for keyword in ACCOUNT_TAKEOVER_KEYWORDS)
