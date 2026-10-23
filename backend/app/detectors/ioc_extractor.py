"""
CyberSage AI — Forensic IOC Extractor & Defanger

High-performance regex-based extraction of Indicators of Compromise (IOCs)
from raw incident telemetry logs.

EXTRACTED ARTIFACT TYPES:
- IPv4 / IPv6 addresses, classified into RFC 1918 private vs WAN public
- Fully Qualified Domain Names (FQDNs)
- HTTP/HTTPS URLs
- File Hashes: MD5 (32 hex), SHA1 (40 hex), SHA256 (64 hex)
- CVE identifiers (CVE-YYYY-NNNNN)
- AWS Access Keys (AKIA...) and IAM ARNs

SAFETY DEFANGING:
IOC defanging converts dangerous indicators into display-safe representations
to prevent accidental clicks or execution by security staff reading reports:
  - http:// → hxxp://
  - https:// → hxxps://
  - evil.com → evil[.]com

RFC 1918 CLASSIFICATION:
Private (internal) IP ranges per RFC 1918:
  - 10.0.0.0/8      (Class A private)
  - 172.16.0.0/12   (Class B private)
  - 192.168.0.0/16  (Class C private)
  - 127.0.0.0/8     (Loopback — excluded from external threat tracking)
"""

import ipaddress
import re
from app.schemas.incident import ExtractedIOCs


# ==============================================================================
# Compiled Regex Patterns (compiled once at module import for performance)
# ==============================================================================

_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)

_RE_IPV6 = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"
    r"|::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"
)

_RE_URL = re.compile(
    r"https?://[^\s\x00-\x1f\x7f\"'<>{}|\\^`\[\]]{3,}"
)

_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|gov|edu|co|uk|de|ru|cn|xyz|zip|app|dev|onion|tech|info|biz|club)\b"
)

# SHA256: 64 hex chars, SHA1: 40 hex chars, MD5: 32 hex chars
_RE_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")
_RE_SHA1 = re.compile(r"\b[0-9a-fA-F]{40}\b")
_RE_MD5 = re.compile(r"\b[0-9a-fA-F]{32}\b")

_RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

_RE_AWS_KEY = re.compile(r"\b(?:AKIA|AROA|ASIA|AIPA|ANPA|ANVA|APKA)[0-9A-Z]{16}\b")
_RE_AWS_ARN = re.compile(r"\barn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[a-zA-Z0-9_/:\-]+")

# RFC 1918 private networks
_PRIVATE_NETWORKS = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),  # Link-local
    ipaddress.IPv4Network("100.64.0.0/10"),   # Carrier-grade NAT
]


# ==============================================================================
# IP Classification Helpers
# ==============================================================================

def _is_private_ip(ip_str: str) -> bool:
    """Returns True if the IPv4 address falls within RFC 1918 private ranges."""
    try:
        addr = ipaddress.IPv4Address(ip_str)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


# ==============================================================================
# IOC Defanging
# ==============================================================================

def defang_url(url: str) -> str:
    """
    Converts a URL into an analyst-safe defanged representation.
    Prevents accidental click-through when shared in reports and ticketing systems.

    Examples:
      http://evil.com/payload → hxxp://evil[.]com/payload
      https://malware.io/load → hxxps://malware[.]io/load
    """
    defanged = url.replace("https://", "hxxps://").replace("http://", "hxxp://")
    # Replace dots in domain portion only (up to first path separator)
    parts = defanged.split("/", 3)
    if len(parts) >= 3:
        parts[2] = parts[2].replace(".", "[.]")
        return "/".join(parts)
    return defanged.replace(".", "[.]")


def defang_domain(domain: str) -> str:
    """Converts a domain to defanged representation: evil.com → evil[.]com"""
    return domain.replace(".", "[.]")


# ==============================================================================
# Main IOC Extractor Class
# ==============================================================================

class IOCExtractor:
    """
    Extracts and classifies all Indicators of Compromise from raw incident telemetry.
    Designed to be fast and stateless — can be safely called concurrently.
    """

    def extract(self, text: str) -> ExtractedIOCs:
        """
        Run all IOC extraction patterns against the provided text.
        Returns a fully populated ExtractedIOCs instance.
        """
        # --- IP Addresses ---
        all_ipv4 = list(dict.fromkeys(_RE_IPV4.findall(text)))  # preserves order, deduplicates
        private_ips = [ip for ip in all_ipv4 if _is_private_ip(ip)]
        public_ips = [ip for ip in all_ipv4 if not _is_private_ip(ip)]

        all_ipv6 = list(dict.fromkeys(_RE_IPV6.findall(text)))

        # --- URLs (extract before domains to avoid double-counting) ---
        urls = list(dict.fromkeys(_RE_URL.findall(text)))
        defanged_urls = [defang_url(u) for u in urls]

        # --- Domains (exclude those already captured as full URLs) ---
        raw_domains = list(dict.fromkeys(_RE_DOMAIN.findall(text)))
        url_hosts = {u.split("/")[2] for u in urls if len(u.split("/")) >= 3}
        domains = [d for d in raw_domains if d not in url_hosts]

        # --- File Hashes (match longer first to avoid collision) ---
        sha256 = list(dict.fromkeys(_RE_SHA256.findall(text)))
        sha1 = [h for h in dict.fromkeys(_RE_SHA1.findall(text)) if h not in sha256]
        md5 = [h for h in dict.fromkeys(_RE_MD5.findall(text)) if h not in sha256 and h not in sha1]
        file_hashes = sha256 + sha1 + md5

        # --- CVE Identifiers ---
        cve_ids = list(dict.fromkeys(_RE_CVE.findall(text)))

        # --- Cloud Identity Artifacts ---
        aws_keys = _RE_AWS_KEY.findall(text)
        aws_arns = _RE_AWS_ARN.findall(text)
        cloud_identities = list(dict.fromkeys([m if isinstance(m, str) else m[0]
                                               for m in aws_keys + aws_arns]))

        return ExtractedIOCs(
            ipv4_addresses=all_ipv4,
            ipv6_addresses=all_ipv6,
            private_ips=private_ips,
            public_ips=public_ips,
            domains=domains,
            urls=urls,
            defanged_urls=defanged_urls,
            file_hashes=file_hashes,
            cve_ids=cve_ids,
            cloud_identities=cloud_identities,
        )
