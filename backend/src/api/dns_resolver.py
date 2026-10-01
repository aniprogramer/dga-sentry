"""
Live External DNS Resolution & Passive Threat Status Enrichment.

Provides non-blocking, fail-safe DNS queries using dnspython with strict
timeouts to distinguish active C2 rendezvous points from dormant/pre-computed
NXDOMAIN candidates.
"""

import logging
import time
from typing import Any

import dns.exception
import dns.resolver

logger = logging.getLogger(__name__)

DEFAULT_NAMESERVERS = ["1.1.1.1", "8.8.8.8"]
DEFAULT_TIMEOUT = 2.0


def compute_threat_summary(
    risk_tier: str,
    operational_status: str,
    ips: list[str],
) -> str:
    """
    Formulate an actionable threat summary for SOC analysts based on the ML
    risk tier and live DNS operational status.
    """
    if operational_status == "active":
        ip_str = ", ".join(ips[:3]) if ips else "Unknown"
        if len(ips) > 3:
            ip_str += f" (+{len(ips) - 3} more)"

        if risk_tier == "malicious":
            return (
                f"Active C2 Server: Resolving to IP(s) [{ip_str}] — "
                "Immediate Network Block Recommended"
            )
        elif risk_tier == "suspicious":
            return (
                f"Active Suspicious Host: Resolving to IP(s) [{ip_str}] — "
                "Endpoint Monitoring & Packet Capture Recommended"
            )
        else:
            return f"Legitimate Active Domain: Normal resolution to [{ip_str}]"

    elif operational_status == "nxdomain":
        if risk_tier in ("malicious", "suspicious"):
            return (
                "Dormant DGA: NXDOMAIN (Unregistered / Pre-computed rendezvous point)"
            )
        else:
            return "Inactive Domain: Authoritative NXDOMAIN returned"

    elif operational_status == "unresolved":
        return "Unresolved Host: No A/AAAA records returned (NoAnswer or NoNameservers)"

    elif operational_status == "timeout":
        return "Resolution Timeout: DNS query timed out before upstream answered"

    else:
        return "Resolution Error: Upstream DNS lookup encountered an error"


def resolve_domain_dns(
    domain: str,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """
    Query DNS records (A, AAAA, NS, MX) for a given domain using strict timeouts.

    Ensures fail-safe execution: network issues, timeouts, or invalid queries
    never raise unhandled exceptions and instead return structured status.
    """
    resolver = dns.resolver.Resolver()
    resolver.nameservers = list(DEFAULT_NAMESERVERS)
    resolver.timeout = timeout
    resolver.lifetime = timeout

    t0 = time.perf_counter()
    ips: list[str] = []
    ns: list[str] = []
    mx: list[str] = []
    status = "unresolved"

    try:
        # 1. Query A records
        answers = resolver.resolve(domain, "A")
        ips.extend(r.to_text() for r in answers)
    except dns.resolver.NXDOMAIN:
        status = "nxdomain"
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        status = "unresolved"
    except dns.exception.Timeout:
        status = "timeout"
    except Exception as exc:
        logger.debug("DNS A resolution failed for %s: %s", domain, exc)
        status = "error"

    # If no A records and status is unresolved, check for AAAA IPv6 records
    if status == "unresolved" and not ips:
        try:
            answers_aaaa = resolver.resolve(domain, "AAAA")
            ips.extend(r.to_text() for r in answers_aaaa)
        except Exception:
            pass

    if ips:
        status = "active"

    # If active or unresolved, attempt secondary NS and MX lookups
    if status in ("active", "unresolved"):
        try:
            ns_answers = resolver.resolve(domain, "NS")
            ns.extend(r.to_text().rstrip(".") for r in ns_answers)
        except Exception:
            pass

        try:
            mx_answers = resolver.resolve(domain, "MX")
            mx.extend(r.exchange.to_text().rstrip(".") for r in mx_answers)
        except Exception:
            pass

    latency = round((time.perf_counter() - t0) * 1000, 2)

    return {
        "resolved": len(ips) > 0,
        "operational_status": status,
        "ip_addresses": ips,
        "name_servers": ns,
        "mail_servers": mx,
        "dnssec_validated": False,
        "response_time_ms": latency,
    }
