"""Threat Intelligence model for deterministic enrichment.

The model represents a single Indicator of Compromise (IOC) enriched with
basic context such as classification (internal/external), simulated
reputation, confidence, and a short summary.  Real‑world enrichment would
query external services; for the MVP we keep the logic deterministic.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class ThreatIntelResult(BaseModel):
    """Enriched IOC information.

    Fields:
    * ioc_type – one of ``ipv4``, ``domain``, ``hostname``, ``url``, ``md5``, ``sha1``, ``sha256``, ``email``.
    * value – raw IOC value.
    * classification – ``Internal`` or ``External`` (for IPs) or ``External`` for other types.
    * country – country code if known (empty for internal).
    * asn – autonomous system number (empty for non‑IP IOCs).
    * organization – owning organization (simulated).
    * reputation – simple string (e.g., ``"Unknown"`` or ``"Malicious"``).
    * confidence – ``"Low"``, ``"Medium"`` or ``"High"``.
    * summary – short human‑readable description.
    """

    ioc_type: str = Field(..., description="Type of IOC: ipv4, domain, hostname, url, md5, sha1, sha256, email")
    value: str = Field(..., description="Raw IOC value")
    classification: str = Field(..., description="Internal or External classification")
    country: str = Field("", description="Country code if determined")
    asn: str = Field("", description="ASN number for IP addresses")
    organization: str = Field("", description="Owning organization / provider")
    reputation: str = Field("Unknown", description="Reputation level (deterministic demo)")
    confidence: str = Field("Medium", description="Confidence in enrichment data")
    summary: str = Field("", description="Brief description of the IOC context")
