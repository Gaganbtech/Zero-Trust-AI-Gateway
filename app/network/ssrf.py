import ipaddress
import socket
import urllib.parse
from typing import List, Tuple


# Cloud metadata and forbidden IP networks
FORBIDDEN_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),         # Broadcast / "this" network
    ipaddress.ip_network("10.0.0.0/8"),        # RFC 1918 Private
    ipaddress.ip_network("100.64.0.0/10"),     # Carrier-grade NAT
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback IPv4
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local / Cloud Metadata (AWS, Azure, GCP, DigitalOcean)
    ipaddress.ip_network("172.16.0.0/12"),     # RFC 1918 Private
    ipaddress.ip_network("192.0.0.0/24"),      # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),      # TEST-NET-1
    ipaddress.ip_network("192.168.0.0/16"),    # RFC 1918 Private
    ipaddress.ip_network("198.18.0.0/15"),     # Network benchmark tests
    ipaddress.ip_network("198.51.100.0/24"),   # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),    # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),       # Multicast
    ipaddress.ip_network("240.0.0.0/4"),       # Reserved for future use
    ipaddress.ip_network("255.255.255.255/32"),# Broadcast
    # IPv6 Networks
    ipaddress.ip_network("::/128"),            # Unspecified
    ipaddress.ip_network("::1/128"),           # Loopback IPv6
    ipaddress.ip_network("::ffff:0:0/96"),     # IPv4-mapped IPv6
    ipaddress.ip_network("100::/64"),          # Discard-only
    ipaddress.ip_network("2001:db8::/32"),     # Documentation
    ipaddress.ip_network("fc00::/7"),          # Unique local address (ULA)
    ipaddress.ip_network("fe80::/10"),         # Link-local IPv6
    ipaddress.ip_network("ff00::/8"),          # Multicast IPv6
]

FORBIDDEN_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "metadata.internal",
    "instance-data",
    "169.254.169.254",
}


def parse_and_validate_ip(ip_str: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """
    Parses an IP address and rejects non-standard hex/octal representations
    that some parsers dangerously normalize.
    """
    # Strict decimal notation check for IPv4
    parts = ip_str.split(".")
    if len(parts) == 4:
        for part in parts:
            if not part.isdigit() or (len(part) > 1 and part.startswith("0")):
                raise ValueError(f"Dangerous non-standard IP notation detected: {ip_str}")
            val = int(part)
            if not (0 <= val <= 255):
                raise ValueError(f"IP octet out of range: {val}")

    return ipaddress.ip_address(ip_str)


def is_ip_forbidden(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Checks whether an IP falls into loopback, private, link-local, or reserved ranges."""
    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return True
    for network in FORBIDDEN_NETWORKS:
        if ip in network:
            return True
    return False


def validate_destination_safety(
    url: str,
    allowed_domains: List[str]
) -> Tuple[str, str, List[str]]:
    """
    Validates that a URL is completely safe from SSRF attacks, DNS rebinding,
    and forbidden networks.
    
    Returns: (normalized_url, hostname, resolved_safe_ips)
    Raises ValueError with specific security reason code if unsafe.
    """
    if not url or not isinstance(url, str):
        raise ValueError("ssrf_empty_url")

    parsed = urllib.parse.urlsplit(url)

    # 1. Scheme check: only http and https permitted
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError(f"ssrf_disallowed_scheme_{parsed.scheme}")

    # 2. Credential leakage in URL
    if parsed.username or parsed.password:
        raise ValueError("ssrf_credentials_in_url")

    hostname = (parsed.hostname or "").lower().strip()
    if not hostname:
        raise ValueError("ssrf_missing_hostname")

    # 3. Forbidden hostnames (localhost, metadata, etc.)
    if hostname in FORBIDDEN_HOSTNAMES or hostname.endswith(".local") or hostname.endswith(".internal"):
        raise ValueError("ssrf_forbidden_hostname")

    # 4. Check domain allowlist
    domain_allowed = False
    for allowed in allowed_domains:
        allowed = allowed.lower().strip()
        if hostname == allowed or hostname.endswith("." + allowed):
            domain_allowed = True
            break
    if not domain_allowed:
        raise ValueError(f"ssrf_domain_not_allowlisted_{hostname}")

    # 5. Resolve DNS and validate every returned IP
    resolved_ips: List[str] = []
    try:
        addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for family, _, _, _, sockaddr in addr_info:
            ip_str = sockaddr[0]
            ip_obj = parse_and_validate_ip(ip_str)
            if is_ip_forbidden(ip_obj):
                raise ValueError(f"ssrf_forbidden_ip_range_{ip_str}")
            resolved_ips.append(ip_str)
    except socket.gaierror as e:
        raise ValueError(f"ssrf_dns_resolution_failed_{str(e)}")

    if not resolved_ips:
        raise ValueError("ssrf_no_resolved_ips")

    return url, hostname, list(set(resolved_ips))
