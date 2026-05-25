"""
IOC Extraction Engine — Module 4

Extracts Indicators of Compromise (IOCs) from raw alert text using
regex-based pattern matching. Supports:
  - IPv4 addresses (excludes private/reserved ranges)
  - URLs (HTTP/HTTPS)
  - Domains
  - File hashes (MD5, SHA1, SHA256)
  - Email addresses

Returns typed IOC objects with category labels and deduplication.
"""

import re
import logging
from dataclasses import dataclass
from typing import Optional
from ipaddress import ip_address, IPv4Address
from config import settings

logger = logging.getLogger(__name__)


@dataclass
class IOC:
    """Represents a single Indicator of Compromise."""

    value: str
    ioc_type: str  # ip, url, domain, hash_md5, hash_sha1, hash_sha256, email
    source_alert_id: str
    context: str = ""  # Surrounding text where IOC was found
    is_private: bool = False

    def to_dict(self) -> dict:
        return {
            "value": self.value,
            "ioc_type": self.ioc_type,
            "source_alert_id": self.source_alert_id,
            "context": self.context,
            "is_private": self.is_private,
        }


class IOCExtractor:
    """
    Regex-based IOC extraction engine.

    Extracts IPs, URLs, domains, file hashes, and email addresses
    from raw alert text. Filters out private/reserved IPs and
    deduplicates results.
    """

    # ── Regex Patterns ──────────────────────────────────────────

    # IPv4 — captures standard dotted notation
    IP_PATTERN = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b"
    )

    # URL — HTTP/HTTPS with path
    URL_PATTERN = re.compile(r'https?://[^\s<>"\')\]},;]+', re.IGNORECASE)

    # Domain — standard domain format (excludes IPs)
    DOMAIN_PATTERN = re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"
        r"+(?:com|net|org|xyz|info|io|co|biz|ru|cn|tk|ml|ga|cf|gq|top"
        r"|club|online|site|tech|store|app|dev|me)\b",
        re.IGNORECASE,
    )

    # File Hashes
    SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")
    SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
    MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")

    # Email
    EMAIL_PATTERN = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")

    # Private/reserved IP ranges to exclude
    PRIVATE_RANGES = [
        re.compile(r"^10\."),
        re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
        re.compile(r"^192\.168\."),
        re.compile(r"^127\."),
        re.compile(r"^0\."),
        re.compile(r"^169\.254\."),
        re.compile(r"^255\."),
    ]

    # Common false-positive domains to exclude are in settings.DOMAIN_WHITELIST

    def __init__(self, extract_private_ips: bool = False):
        """
        Args:
            extract_private_ips: If True, include private IPs in results
                                 (marked with is_private=True).
        """
        self.extract_private_ips = extract_private_ips
        self._seen: set = set()  # For deduplication (type, value)
        logger.info("IOCExtractor initialized")

    def extract_from_alert(self, alert) -> list[IOC]:
        """
        Extract all IOCs from a single Alert object.

        Args:
            alert: Alert dataclass with raw_log field.

        Returns:
            List of deduplicated IOC objects.
        """
        text = alert.raw_log
        alert_id = alert.alert_id
        iocs = []

        # Also check src_ip and dst_ip fields directly
        for ip_field in [alert.src_ip, alert.dst_ip]:
            if ip_field:
                ip_ioc = self._create_ip_ioc(
                    ip_field, alert_id, f"Alert field: {ip_field}"
                )
                if ip_ioc:
                    iocs.append(ip_ioc)

        # Extract from raw log text
        iocs.extend(self._extract_ips(text, alert_id))
        iocs.extend(self._extract_urls(text, alert_id))
        iocs.extend(self._extract_domains(text, alert_id))
        iocs.extend(self._extract_hashes(text, alert_id))
        iocs.extend(self._extract_emails(text, alert_id))

        logger.info(f"Extracted {len(iocs)} IOCs from alert {alert_id}")
        return iocs

    def extract_from_text(self, text: str, source_id: str = "manual") -> list[IOC]:
        """
        Extract IOCs from raw text.

        Args:
            text: Raw text to extract IOCs from.
            source_id: Identifier for the source of the text.

        Returns:
            List of deduplicated IOC objects.
        """
        iocs = []
        iocs.extend(self._extract_ips(text, source_id))
        iocs.extend(self._extract_urls(text, source_id))
        iocs.extend(self._extract_domains(text, source_id))
        iocs.extend(self._extract_hashes(text, source_id))
        iocs.extend(self._extract_emails(text, source_id))
        return iocs

    def extract_batch(self, alerts: list) -> list[IOC]:
        """
        Extract IOCs from multiple alerts.

        Args:
            alerts: List of Alert objects.

        Returns:
            Consolidated, deduplicated list of IOC objects.
        """
        all_iocs = []
        for alert in alerts:
            all_iocs.extend(self.extract_from_alert(alert))
        logger.info(
            f"Batch extraction complete: {len(all_iocs)} total IOCs from {len(alerts)} alerts"
        )
        return all_iocs

    # ── Private extraction methods ───────────────────────────────

    def _extract_ips(self, text: str, source_id: str) -> list[IOC]:
        """Extract IPv4 addresses from text."""
        iocs = []
        for match in self.IP_PATTERN.finditer(text):
            ip_str = match.group()
            ioc = self._create_ip_ioc(ip_str, source_id, self._get_context(text, match))
            if ioc:
                iocs.append(ioc)
        return iocs

    def _create_ip_ioc(
        self, ip_str: str, source_id: str, context: str
    ) -> Optional[IOC]:
        """Create an IP IOC with validation and dedup."""
        is_private = self._is_private_ip(ip_str)

        if is_private and not self.extract_private_ips:
            return None

        dedup_key = ("ip", ip_str)
        if dedup_key in self._seen:
            return None
        self._seen.add(dedup_key)

        return IOC(
            value=ip_str,
            ioc_type="ip",
            source_alert_id=source_id,
            context=context,
            is_private=is_private,
        )

    def _extract_urls(self, text: str, source_id: str) -> list[IOC]:
        """Extract URLs from text."""
        iocs = []
        for match in self.URL_PATTERN.finditer(text):
            url = match.group().rstrip(".,;:)'\"")
            dedup_key = ("url", url)
            if dedup_key in self._seen:
                continue
            self._seen.add(dedup_key)

            iocs.append(
                IOC(
                    value=url,
                    ioc_type="url",
                    source_alert_id=source_id,
                    context=self._get_context(text, match),
                )
            )
        return iocs

    def _extract_domains(self, text: str, source_id: str) -> list[IOC]:
        """Extract domain names from text (excludes URLs and whitelisted domains)."""
        iocs = []
        # Get domains already captured in URLs to avoid duplicates
        url_domains = set()
        for match in self.URL_PATTERN.finditer(text):
            url = match.group()
            domain_match = re.search(r"https?://([^/:\s]+)", url)
            if domain_match:
                url_domains.add(domain_match.group(1).lower())

        for match in self.DOMAIN_PATTERN.finditer(text):
            domain = match.group().lower()
            if domain in url_domains:
                continue
            if domain in settings.DOMAIN_WHITELIST:
                continue

            dedup_key = ("domain", domain)
            if dedup_key in self._seen:
                continue
            self._seen.add(dedup_key)

            iocs.append(
                IOC(
                    value=domain,
                    ioc_type="domain",
                    source_alert_id=source_id,
                    context=self._get_context(text, match),
                )
            )
        return iocs

    def _extract_hashes(self, text: str, source_id: str) -> list[IOC]:
        """Extract file hashes (SHA256, SHA1, MD5) from text."""
        iocs = []
        found_hashes = set()

        # SHA256 first (longest, most specific)
        for match in self.SHA256_PATTERN.finditer(text):
            hash_val = match.group().lower()
            if hash_val not in found_hashes:
                found_hashes.add(hash_val)
                dedup_key = ("hash_sha256", hash_val)
                if dedup_key not in self._seen:
                    self._seen.add(dedup_key)
                    iocs.append(
                        IOC(
                            value=hash_val,
                            ioc_type="hash_sha256",
                            source_alert_id=source_id,
                            context=self._get_context(text, match),
                        )
                    )

        # SHA1 (40 chars — exclude substrings of SHA256)
        for match in self.SHA1_PATTERN.finditer(text):
            hash_val = match.group().lower()
            if hash_val not in found_hashes and not any(
                hash_val in h for h in found_hashes if len(h) == 64
            ):
                found_hashes.add(hash_val)
                dedup_key = ("hash_sha1", hash_val)
                if dedup_key not in self._seen:
                    self._seen.add(dedup_key)
                    iocs.append(
                        IOC(
                            value=hash_val,
                            ioc_type="hash_sha1",
                            source_alert_id=source_id,
                            context=self._get_context(text, match),
                        )
                    )

        # MD5 (32 chars — exclude substrings of longer hashes)
        for match in self.MD5_PATTERN.finditer(text):
            hash_val = match.group().lower()
            if hash_val not in found_hashes and not any(
                hash_val in h for h in found_hashes if len(h) > 32
            ):
                found_hashes.add(hash_val)
                dedup_key = ("hash_md5", hash_val)
                if dedup_key not in self._seen:
                    self._seen.add(dedup_key)
                    iocs.append(
                        IOC(
                            value=hash_val,
                            ioc_type="hash_md5",
                            source_alert_id=source_id,
                            context=self._get_context(text, match),
                        )
                    )

        return iocs

    def _extract_emails(self, text: str, source_id: str) -> list[IOC]:
        """Extract email addresses from text."""
        iocs = []
        for match in self.EMAIL_PATTERN.finditer(text):
            email = match.group().lower()
            dedup_key = ("email", email)
            if dedup_key in self._seen:
                continue
            self._seen.add(dedup_key)

            iocs.append(
                IOC(
                    value=email,
                    ioc_type="email",
                    source_alert_id=source_id,
                    context=self._get_context(text, match),
                )
            )
        return iocs

    # ── Utility methods ──────────────────────────────────────────

    def _is_private_ip(self, ip_str: str) -> bool:
        """Check if IP is in a private/reserved range."""
        try:
            addr = ip_address(ip_str)
            if isinstance(addr, IPv4Address):
                return addr.is_private or addr.is_reserved or addr.is_loopback
        except ValueError:
            pass
        return any(pattern.match(ip_str) for pattern in self.PRIVATE_RANGES)

    def _get_context(self, text: str, match: re.Match, window: int = 50) -> str:
        """Get surrounding context for an IOC match."""
        start = max(0, match.start() - window)
        end = min(len(text), match.end() + window)
        context = text[start:end].replace("\n", " ").strip()
        if start > 0:
            context = "..." + context
        if end < len(text):
            context = context + "..."
        return context

    def get_summary(self, iocs: list[IOC]) -> dict:
        """Generate summary statistics for extracted IOCs."""
        summary = {
            "total": len(iocs),
            "by_type": {},
            "unique_values": set(),
        }
        for ioc in iocs:
            summary["by_type"].setdefault(ioc.ioc_type, 0)
            summary["by_type"][ioc.ioc_type] += 1
            summary["unique_values"].add(ioc.value)
        summary["unique_count"] = len(summary["unique_values"])
        del summary["unique_values"]  # Not serializable
        return summary

    def reset(self):
        """Reset deduplication state."""
        self._seen.clear()
        logger.info("IOCExtractor dedup state reset")
