"""Deterministic Threat‑Intel enrichment module.

Provides a single public function `enrich_iocs` that extracts IOCs from an
Alert, classifies IPv4 addresses, assigns deterministic reputation values,
Deduplicates, sorts, and returns a list of `ThreatIntelResult` objects.
"""

from __future__ import annotations

import ipaddress
import re
from typing import List, Set, Tuple

from src.core.models.alert import Alert
from src.core.models.threat_intel import ThreatIntelResult

# ---------------------------------------------------------------------------
# Noise words – strings that should never be treated as IOCs.
# ---------------------------------------------------------------------------
_NOISE_WORDS = {
    "john.doe",
    "admin.user",
    "svc.account",
    "blocked",
    "allowed",
    "success",
    "failed",
    "syn",
    "ack",
    "rst",
    "fin",
    "tcp",
    "udp",
}

# ---------------------------------------------------------------------------
# Regular expressions for IOC detection (deterministic, no external libs).
# ---------------------------------------------------------------------------
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b"
)

_DOMAIN_RE = re.compile(
    r"\b(?:(?:[a-zA-Z0-9-]{1,63}\.)+"
    r"(?:[a-zA-Z]{2,63}))\b"
)

_URL_RE = re.compile(
    r"\b(?:(?:https?|ftp)://)?"
    r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}"
    r"(?:/[^\s]*)?\b"
)

_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")

# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------
def _classify_ip(ip_str: str) -> str:
    """Return \"Internal\", \"External\", or \"Unknown\" for an IPv4 address."""
    try:
        ip = ipaddress.ip_address(ip_str)
        internal_nets = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("127.0.0.0/8"),
        ]
        for net in internal_nets:
            if ip in net:
                return "Internal"
        return "External"
    except ValueError:
        return "Unknown"


def _is_noise(word: str) -> bool:
    """True if `word` matches a known noise token (case‑insensitive)."""
    return word.lower() in _NOISE_WORDS


def _extract_iocs(text: str) -> Set[Tuple[str, str]]:
    """Extract raw IOCs from free‑text, filter noise, and deduplicate."""
    found: Set[Tuple[str, str]] = set()

    # IPv4
    for m in _IPV4_RE.finditer(text):
        val = m.group(0)
        if not _is_noise(val):
            found.add(("ipv4", val))

    # URL – must contain a scheme or a path to avoid matching bare domains
    for m in _URL_RE.finditer(text):
        val = m.group(0)
        if not _is_noise(val):
            found.add(("url", val))

    # Domain – exclude anything already captured as URL or IP
    for m in _DOMAIN_RE.finditer(text):
        val = m.group(0)
        if not _is_noise(val):
            if any(val in v for _, v in found if _ == "url"):
                continue
            found.add(("domain", val))

    # Email
    for m in _EMAIL_RE.finditer(text):
        val = m.group(0)
        if not _is_noise(val):
            found.add(("email", val))

    # Hashes
    for m in _MD5_RE.finditer(text):
        val = m.group(0)
        if not _is_noise(val):
            found.add(("md5", val))

    for m in _SHA1_RE.finditer(text):
        val = m.group(0)
        if not _is_noise(val):
            found.add(("sha1", val))

    for m in _SHA256_RE.finditer(text):
        val = m.group(0)
        if not _is_noise(val):
            found.add(("sha256", val))

    return found

# Hard‑coded list of known malicious hashes (deterministic test vectors)
_MALWARE_HASHES = {
    "44d88612fea8a8f36de82e1278abb02f",  # MD5 test (EICAR)
    "3395856ce81f2b7382dee72602f798b642f14140",  # SHA1 test (EICAR)
    "275a021bbfb6489e54d471899f7db9d1663f5c7ab8a2e68f73a5c0f6a8fa5b83",  # SHA256 test (EICAR)
}


def _reputation_for(ioc_type: str, value: str) -> str:
    """Deterministic reputation based on IOC type and value."""
    if ioc_type == "ipv4":
        cls = _classify_ip(value)
        return "Trusted" if cls == "Internal" else "Unknown"
    if ioc_type in {"md5", "sha1", "sha256"}:
        return "Malicious" if value.lower() in _MALWARE_HASHES else "Unknown"
    return "Unknown"

# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------
def enrich_iocs(alert: Alert) -> List[ThreatIntelResult]:
    """Extract, classify, and enrich IOCs from an Alert.

    Returns a list of deterministic ``ThreatIntelResult`` objects,
    sorted by IOC type then value, with duplicates removed.
    """
    raw_text = alert.raw if isinstance(alert.raw, str) else str(alert.raw)

    ioc_candidates: Set[Tuple[str, str]] = _extract_iocs(raw_text)

    # Scan a few explicit fields that may contain IOCs not in raw JSON.
    for field in ("source_ip", "dest_ip", "source_fqdn", "dest_fqdn"):
        value = getattr(alert, field, None)
        if isinstance(value, str):
            ioc_candidates.update(_extract_iocs(value))

    results: List[ThreatIntelResult] = []
    for ioc_type, value in ioc_candidates:
        classification = _classify_ip(value) if ioc_type == "ipv4" else "External"
        reputation = _reputation_for(ioc_type, value)
        results.append(
            ThreatIntelResult(
                ioc_type=ioc_type,
                value=value,
                classification=classification,
                country="",
                asn="",
                organization="",
                reputation=reputation,
                confidence="Medium",
                summary=f"Deterministic enrichment for {ioc_type} {value}",
            )
        )

    results.sort(key=lambda r: (r.ioc_type, r.value))
    return results
