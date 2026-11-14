import ipaddress
import re
from urllib.parse import urlparse


def _is_private_or_reserved(host):
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast


_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9\-\.]{0,251}[A-Za-z0-9])?$")


def is_private_target(host):
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False


def is_safe_target(host):
    """Return True only for routable public DNS names and routable public IPs.

    Blocks: loopback, link-local, private, reserved, multicast, and DNS names
    that resolve to any of those, as well as any host containing a URL scheme.
    """
    if not host or len(host) > 253:
        return False
    if not _HOSTNAME_RE.match(host):
        return False
    if _is_private_or_reserved(host):
        return False

    # Block hostnames that embed a scheme or dangerous separators (SSRF bypass).
    if re.search(r"^[A-Za-z][A-Za-z0-9+.-]*://", host) or "//" in host:
        return False

    try:
        resolved = ipaddress.ip_address(host)
    except ValueError:
        # Must be a DNS name; resolve it and check the answers.
        from dns import resolver, exception as dns_exception

        try:
            answers = resolver.resolve(host, "A")
            return not any(_is_private_or_reserved(str(r)) for r in answers)
        except (resolver.NXDOMAIN, resolver.NoAnswer, dns_exception.NotImplementedError, dns_exception.Timeout):
            return False
        except Exception:
            return False
    return not (_is_private_or_reserved(str(resolved)) or resolved.is_loopback or resolved.is_link_local or resolved.is_reserved or resolved.is_multicast)


def normalize_target(value):
    """Normalize and validate a scan target (domain, URL, or IP)."""
    value = value.strip()
    if not value:
        raise ValueError("A target is required.")

    if "://" in value:
        parsed = urlparse(value)
        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https"):
            raise ValueError("Use http:// or https:// for scanning a web/resource target.")
        host = parsed.hostname
        if not host:
            raise ValueError("Enter a valid domain, URL, or IP address.")
    else:
        host = value

    if not host or len(host) > 253:
        raise ValueError("Enter a valid domain, URL, or IP address.")

    if not is_safe_target(host):
        raise ValueError(
            "This target is not allowed for scanning. Only public, routable targets are accepted. "
            "Confirm you own or are authorized to assess the target before retrying."
        )
    return host


def authorization_notice():
    return "Run scans only against systems you own or are explicitly authorized to assess."
