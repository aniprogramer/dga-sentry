"""
Domain input normalization and validation (server-side source of truth).

Pure functions, no I/O. The frontend mirrors these rules in
frontend/src/lib/domain.ts; both are checked against shared/domain_cases.json.
Validation only says whether an input CAN be analyzed. It never judges a
domain as safe or malicious.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import re
import unicodedata

import idna
import tldextract

MAX_DOMAIN_LEN = 253
MAX_LABEL_LEN = 63
MAX_RAW_LEN = 2048  # cap work on absurd input before normalization

MESSAGES: dict[str, str] = {
    "EMPTY": "Enter a domain name.",
    "INVALID_CHARACTER": "Domain contains a character that is not allowed.",
    "TOO_LONG": "Domain is longer than 253 characters.",
    "LABEL_TOO_LONG": "A label is longer than 63 characters.",
    "EMPTY_LABEL": "Domain has an empty label (two dots in a row or a leading dot).",
    "HYPHEN_POSITION": "A label cannot start or end with a hyphen.",
    "INVALID_PUNYCODE": "A label has invalid punycode or an invalid internationalized form.",
    "IS_IP_ADDRESS": "This tool analyzes domain names, not IP addresses.",
    "INVALID_TLD": "The top-level domain cannot be all digits.",
    "SINGLE_LABEL": "Enter a full domain with a dot, such as example.com.",
    "EMPTY_BATCH": "Provide at least one domain.",
    "TOO_MANY_DOMAINS": "Too many domains. The maximum is 100 per request.",
    "EMAIL_ADDRESS": "This looks like an email address. Enter a domain name instead.",
}

NOTE_MESSAGES: dict[str, str] = {
    "EXTRACTED_FROM_URL": "Analyzing the hostname extracted from the text you entered.",
    "WILDCARD_STRIPPED": "Leading wildcard (*.) removed.",
    "RESERVED_NAME": "Reserved or special-use name. The model verdict is not meaningful for it.",
    "NORMALIZED": "Input was normalized (case, trailing dot or internationalized form).",
}

WARNING_MESSAGES: dict[str, str] = {
    "UNDERSCORE": "Contains an underscore. Valid in DNS records, but not a valid hostname.",
    "VERY_SHORT": "Very short name (under 4 characters). Little signal for analysis.",
    "DIGIT_HEAVY": "Name is mostly digits.",
    "LONG_LABEL": "Very long subdomain label. This pattern is also seen in DNS tunneling.",
    "DEEP_SUBDOMAINS": "Deeply nested subdomains.",
    "PRIVATE_SUFFIX": "Hosted under a private suffix (shared hosting platform).",
    "HOMOGRAPH": "A label mixes scripts, which can imitate another name.",
}

_RESERVED_SUFFIXES = (
    "test", "example", "invalid", "localhost", "local", "onion", "internal",
    "home.arpa", "in-addr.arpa", "ip6.arpa",
    "example.com", "example.net", "example.org",
)
_LABEL_RE = re.compile(r"^[a-z0-9_-]+$")
_NUMERIC_PART_RE = re.compile(r"^(?:0x[0-9a-f]+|[0-9]+)$")
_LONG_LABEL = 30
_DEEP_SUBDOMAINS = 4

_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)  # bundled PSL, offline


class DomainError(ValueError):
    def __init__(self, code: str):
        super().__init__(MESSAGES[code])
        self.code = code
        self.message = MESSAGES[code]


@dataclass
class DomainInfo:
    original: str
    ascii: str
    display: str
    notes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    registrable_domain: str | None = None
    subdomain_depth: int = 0
    is_punycode: bool = False


def safe_input(raw: object, limit: int = 100) -> str:
    """Escaped, truncated copy of raw input safe to echo back or log."""
    s = raw if isinstance(raw, str) else repr(raw)
    s = s[:limit]
    return "".join(
        c if c.isprintable() and c not in "<>&\"'" else f"\\u{ord(c):04x}" for c in s
    )


def _extract_host(s: str) -> tuple[str, bool]:
    """Strip scheme, credentials, port, path, query, fragment. Returns (host, changed)."""
    orig = s
    if "://" in s:
        s = s.split("://", 1)[1]
    for sep in "/?#":
        s = s.split(sep, 1)[0]
    s = s.rsplit("@", 1)[-1]
    if s.startswith("["):
        end = s.find("]")
        s = s[1:end] if end != -1 else s
    elif s.count(":") == 1:
        s = s.split(":", 1)[0]
    return s, s != orig


def _is_ipv4_like(host: str) -> bool:
    parts = host.split(".")
    return len(parts) <= 4 and all(_NUMERIC_PART_RE.match(p) for p in parts)


def _is_ip(host: str) -> bool:
    if ":" in host:
        try:
            ipaddress.IPv6Address(host.split("%", 1)[0])
            return True
        except ValueError:
            return False
    return _is_ipv4_like(host)


def _script(ch: str) -> str | None:
    if not ch.isalpha():
        return None
    try:
        return unicodedata.name(ch).split()[0]
    except ValueError:
        return None


def _to_ascii_label(label: str) -> str:
    if label.isascii():
        return label
    try:
        return idna.alabel(label).decode("ascii")
    except idna.InvalidCodepoint:
        raise DomainError("INVALID_CHARACTER") from None
    except idna.IDNAError as e:
        raise DomainError("LABEL_TOO_LONG" if "too long" in str(e).lower() else "INVALID_PUNYCODE") from None


def normalize_and_validate(raw: object) -> DomainInfo:
    """Normalize raw input to a canonical domain and validate it. Raises DomainError."""
    if not isinstance(raw, str):
        raise DomainError("INVALID_CHARACTER")
    if len(raw) > MAX_RAW_LEN:
        raise DomainError("TOO_LONG")
    s = raw.strip()
    if not s:
        raise DomainError("EMPTY")
    if any(c.isspace() or unicodedata.category(c) == "Cc" for c in s):
        raise DomainError("INVALID_CHARACTER")

    notes: list[str] = []
    if "@" in s and "://" not in s and not any(c in s for c in "/?#"):
        raise DomainError("EMAIL_ADDRESS")
    host, changed = _extract_host(s)
    if changed:
        notes.append("EXTRACTED_FROM_URL")
    if not host:
        raise DomainError("EMPTY")

    normalized = False
    if host != host.lower():
        normalized = True
    host = host.lower()
    if host.endswith("."):
        host = host[:-1]
        normalized = True
        if not host:
            raise DomainError("EMPTY")
    if host.startswith("*."):
        host = host[2:]
        notes.append("WILDCARD_STRIPPED")
        if not host:
            raise DomainError("EMPTY")

    if _is_ip(host):
        raise DomainError("IS_IP_ADDRESS")

    if not host.isascii():
        try:
            host = idna.uts46_remap(unicodedata.normalize("NFC", host), std3_rules=False, transitional=False)
        except idna.InvalidCodepoint:
            raise DomainError("INVALID_CHARACTER") from None
        host = unicodedata.normalize("NFC", host).replace("。", ".").replace("．", ".").replace("｡", ".")
        normalized = True
    labels = host.split(".")
    ascii_labels = [_to_ascii_label(lb) for lb in labels]
    ascii_name = ".".join(ascii_labels)

    # Checks run rule-by-rule over the whole name, in spec order.
    if len(ascii_name) > MAX_DOMAIN_LEN:
        raise DomainError("TOO_LONG")
    if any(not lb for lb in ascii_labels):
        raise DomainError("EMPTY_LABEL")
    if any(len(lb) > MAX_LABEL_LEN for lb in ascii_labels):
        raise DomainError("LABEL_TOO_LONG")
    if any(not _LABEL_RE.match(lb) for lb in ascii_labels):
        raise DomainError("INVALID_CHARACTER")
    if any(lb.startswith("-") or lb.endswith("-") for lb in ascii_labels):
        raise DomainError("HYPHEN_POSITION")

    display_labels: list[str] = []
    is_puny = False
    for lb in ascii_labels:
        if lb[2:4] == "--":
            if not lb.startswith("xn--"):
                raise DomainError("INVALID_PUNYCODE")
            try:
                display_labels.append(idna.ulabel(lb))
            except idna.IDNAError:
                raise DomainError("INVALID_PUNYCODE") from None
            is_puny = True
        else:
            display_labels.append(lb)
    display = ".".join(display_labels)

    if len(ascii_labels) < 2:
        raise DomainError("SINGLE_LABEL")
    if ascii_labels[-1].isdigit():
        raise DomainError("INVALID_TLD")

    if normalized:
        notes.append("NORMALIZED")
    if any(ascii_name == r or ascii_name.endswith("." + r) for r in _RESERVED_SUFFIXES):
        notes.append("RESERVED_NAME")

    info = DomainInfo(original=raw, ascii=ascii_name, display=display, notes=notes, is_punycode=is_puny)
    _add_analysis_fields(info, ascii_labels, display_labels)
    return info


def _add_analysis_fields(info: DomainInfo, ascii_labels: list[str], display_labels: list[str]) -> None:
    ext = _extract(info.ascii, include_psl_private_domains=True)
    sld = ext.domain
    sub_labels = ext.subdomain.split(".") if ext.subdomain else []
    if not ext.suffix:  # unknown TLD: treat last label as the suffix
        sld = ascii_labels[-2]
        sub_labels = ascii_labels[:-2]
        info.registrable_domain = ".".join(ascii_labels[-2:])
    else:
        info.registrable_domain = f"{sld}.{ext.suffix}"
    info.subdomain_depth = len(sub_labels)
    w = info.warnings
    if any("_" in lb for lb in ascii_labels):
        w.append("UNDERSCORE")
    sld_disp = idna.ulabel(sld) if sld.startswith("xn--") else sld
    if sld_disp and len(sld_disp) < 4:
        w.append("VERY_SHORT")
    if len(sld_disp) >= 4 and sum(c.isdigit() for c in sld_disp) / len(sld_disp) >= 0.5:
        w.append("DIGIT_HEAVY")
    if any(len(lb) > _LONG_LABEL for lb in sub_labels):
        w.append("LONG_LABEL")
    if info.subdomain_depth >= _DEEP_SUBDOMAINS:
        w.append("DEEP_SUBDOMAINS")
    if ext.is_private:
        w.append("PRIVATE_SUFFIX")
    for lb in display_labels:
        if len({s for s in map(_script, lb) if s}) > 1:
            w.append("HOMOGRAPH")
            break
