"""Detection of automated email-security scanners (Microsoft Safe Links,
Zscaler, Proofpoint URL Defense, Mimecast, Barracuda, ...) hitting tracking
endpoints, so their pre-fetch requests can be excluded from "real human"
click/open telemetry.

Signals used, in order of confidence:
  1. Source IP falls inside a vendor's published CIDR range (high confidence).
     Ranges are refreshed offline by scripts/update_scanner_ranges.py into
     data/scanner_ranges.json — this module only reads that cache, it never
     makes a network call on the request path.
  2. Reverse DNS (PTR) hostname ends in a known vendor suffix (high confidence).
  3. Source IP's ASN (via Team Cymru's DNS whois) is one of a short, verified
     list of a vendor's own corporate ASNs (high confidence) — this is what
     catches a hit like 74.224.61.38, which is Microsoft-owned (AS8075) but
     outside the narrow Exchange Online Protection range that's all the SPF
     chain in update_scanner_ranges.py can see. Only vendors whose ASN space
     is overwhelmingly backend/security infra (not consumer ISP/cloud-tenant
     space like general AWS/Azure) are listed, to keep false positives rare.
  4. User-Agent string matches a known scanner signature (medium confidence),
     or a generic bot/crawler token (low confidence — not flagged by default,
     since real users occasionally carry odd UAs via corporate proxies).

Being wrong in the "flag a real victim as a scanner" direction hides a real
click, so every match that drives is_scanner=True is high- or medium-confidence
only, and the reason/vendor is always stored so a human can audit the call.
"""

import ipaddress
import json
import os
import re
import socket

try:
    import dns.resolver
except ImportError:
    dns = None

RANGES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "scanner_ranges.json")

# Verified via `dig AS<n>.asn.cymru.com TXT` — only a vendor's own core
# corporate/security-infra ASNs go here, never a generic cloud/ISP ASN
# (AWS, Azure-the-tenant-platform, consumer broadband, ...) since those
# carry huge amounts of unrelated real-human traffic.
KNOWN_ASN_VENDORS = {
    "8075":  "microsoft",   # MICROSOFT-CORP-MSN-AS-BLOCK
    "8068":  "microsoft",   # MICROSOFT-CORP-MSN-AS-BLOCK
    "8069":  "microsoft",   # MICROSOFT-CORP-MSN-AS-BLOCK
    "8070":  "microsoft",   # MICROSOFT-CORP-MSN-AS-BLOCK
    "3598":  "microsoft",   # MICROSOFT-CORP-AS
    "12076": "microsoft",   # MICROSOFT
    "53813": "zscaler",     # ZSCALER-INC
}

# Reverse-DNS PTR suffix -> vendor. These hostnames are operated by the vendor
# and don't change the way IP ranges do, so this list needs little upkeep.
KNOWN_PTR_SUFFIXES = {
    "protection.outlook.com":  "microsoft",
    "outlook.com":             "microsoft",
    "msnbot-outlook.com":      "microsoft",
    "office365.com":           "microsoft",
    "zscaler.net":             "zscaler",
    "zscalerone.net":          "zscaler",
    "zscalertwo.net":          "zscaler",
    "zscalerthree.net":        "zscaler",
    "zscloud.net":             "zscaler",
    "zscalerbeta.net":         "zscaler",
    "zscalergov.net":          "zscaler",
    "pphosted.com":            "proofpoint",
    "proofpoint.com":          "proofpoint",
    "mimecast.com":            "mimecast",
    "barracudanetworks.com":   "barracuda",
    "barracudabrts.com":       "barracuda",
    "symantec.com":            "symantec",
    "messagelabs.com":         "symantec",
    "trendmicro.com":          "trendmicro",
    "googleusercontent.com":   "google",  # Gmail image proxy pre-fetch
}

# User-Agent substrings known to identify an automated scanner/pre-fetcher
# rather than a human-driven browser. (vendor, pattern, confidence)
KNOWN_UA_SIGNATURES = [
    ("microsoft",  r"ips-agent"),
    ("microsoft",  r"Microsoft Office"),
    ("microsoft",  r"Outlook-iOS"),
    ("microsoft",  r"ATP-Safelinks"),
    ("microsoft",  r"MS[- ]?Defender"),
    ("zscaler",    r"Zscaler"),
    ("proofpoint", r"Proofpoint"),
    ("proofpoint", r"pp-url-protection"),
    ("mimecast",   r"Mimecast"),
    ("barracuda",  r"Barracuda"),
    ("symantec",   r"Symantec"),
    ("trendmicro", r"TrendMicro"),
    ("google",     r"GoogleImageProxy"),
]

# Generic bot/crawler tokens. Matching one of these is only ever "low"
# confidence — it is recorded but NOT flagged as is_scanner by default,
# since it also matches things like link-preview bots in chat apps that a
# real victim might trigger by forwarding the email.
GENERIC_BOT_PATTERN = re.compile(r"bot|crawler|spider|curl|wget|python-requests", re.IGNORECASE)

_UA_SIGNATURES_COMPILED = [(vendor, re.compile(pat, re.IGNORECASE)) for vendor, pat in KNOWN_UA_SIGNATURES]


_ranges_cache = {"mtime": None, "data": {}}


def _load_ranges():
    """Vendor -> list of ipaddress networks, read from the cache file written
    by scripts/update_scanner_ranges.py (run periodically via cron). Reloaded
    whenever the file's mtime changes, so a cron refresh takes effect without
    restarting the app. Missing/corrupt file just means IP-range matching is
    skipped (UA + PTR checks still run)."""
    try:
        mtime = os.stat(RANGES_PATH).st_mtime
    except FileNotFoundError:
        return {}

    if mtime == _ranges_cache["mtime"]:
        return _ranges_cache["data"]

    try:
        with open(RANGES_PATH) as f:
            raw = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return _ranges_cache["data"]

    out = {}
    for vendor, cidrs in raw.items():
        if vendor.startswith("_"):
            continue
        nets = []
        for c in cidrs:
            try:
                nets.append(ipaddress.ip_network(c, strict=False))
            except ValueError:
                continue
        if nets:
            out[vendor] = nets

    _ranges_cache["mtime"] = mtime
    _ranges_cache["data"] = out
    return out


def _check_ip_ranges(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for vendor, networks in _load_ranges().items():
        for net in networks:
            if addr in net:
                return vendor
    return None


_reverse_dns_cache = {}


def _reverse_dns(ip):
    """Best-effort PTR lookup with a tight timeout. Never raises.

    Only a DEFINITIVE "no PTR record" answer is cached. A timeout or any
    other transient failure is returned as None but NOT cached — caching it
    would permanently blind this long-running process to that IP (a single
    bad DNS round-trip would look identical to "this IP has no PTR record"
    forever, until the process restarts). Every call is a fresh retry unless
    we're sure the negative answer is real.
    """
    if ip in _reverse_dns_cache:
        return _reverse_dns_cache[ip]

    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(0.5)
        host, _, _ = socket.gethostbyaddr(ip)
        result, cacheable = host.lower(), True
    except socket.herror as e:
        # h_errno 1 = HOST_NOT_FOUND, 4 = NO_DATA: definitive negative.
        # h_errno 2 = TRY_AGAIN, 3 = NO_RECOVERY: transient, don't cache.
        definitive = e.args and e.args[0] in (1, 4)
        result, cacheable = None, bool(definitive)
    except Exception:
        result, cacheable = None, False  # timeout or anything else: retry next time
    finally:
        socket.setdefaulttimeout(old_timeout)

    if cacheable:
        if len(_reverse_dns_cache) >= 4096:
            _reverse_dns_cache.clear()
        _reverse_dns_cache[ip] = result
    return result


def _check_reverse_dns(ip):
    host = _reverse_dns(ip)
    if not host:
        return None, None
    for suffix, vendor in KNOWN_PTR_SUFFIXES.items():
        if host.endswith(suffix):
            return vendor, host
    return None, host


_asn_cache = {}


def _asn_lookup(ip):
    """Best-effort ASN lookup via Team Cymru's DNS whois service — no API
    key, no account, just a TXT query. Tight timeout, never raises.

    Same caching rule as _reverse_dns: only a definitive NXDOMAIN/NoAnswer is
    cached. A timeout or any other transient failure is retried on the next
    call instead of being memoized as a permanent "not a scanner" answer.
    """
    if dns is None:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.version != 4:
        return None  # Cymru's origin service needs a separate v6 query form; not worth it here.

    if ip in _asn_cache:
        return _asn_cache[ip]

    reversed_ip = ".".join(reversed(ip.split(".")))
    try:
        answers = dns.resolver.resolve(f"{reversed_ip}.origin.asn.cymru.com", "TXT", lifetime=0.5)
        txt = b"".join(answers[0].strings).decode()
        result, cacheable = txt.split("|")[0].strip(), True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        result, cacheable = None, True  # definitive: Cymru has no record for this IP
    except Exception:
        result, cacheable = None, False  # timeout, no nameservers, etc: retry next time

    if cacheable:
        if len(_asn_cache) >= 4096:
            _asn_cache.clear()
        _asn_cache[ip] = result
    return result


def _check_asn(ip):
    asn = _asn_lookup(ip)
    if not asn:
        return None, None
    return KNOWN_ASN_VENDORS.get(asn), asn


def _check_user_agent(ua):
    if not ua:
        return None, None
    for vendor, pattern in _UA_SIGNATURES_COMPILED:
        if pattern.search(ua):
            return vendor, pattern.pattern
    if GENERIC_BOT_PATTERN.search(ua):
        return None, "generic-bot-token"
    return None, None


def classify(ip, user_agent):
    """Classify a single hit (tracking-pixel open or link click).

    Returns {"is_scanner": bool, "vendor": str|None, "confidence": str|None,
    "reason": str} — reason is always a short human-readable string, even
    when is_scanner is False, so it can be logged for later review.
    """
    vendor = _check_ip_ranges(ip)
    if vendor:
        return {"is_scanner": True, "vendor": vendor, "confidence": "high",
                "reason": f"ip in published {vendor} range"}

    vendor, host = _check_reverse_dns(ip)
    if vendor:
        return {"is_scanner": True, "vendor": vendor, "confidence": "high",
                "reason": f"reverse dns matches {vendor} ({host})"}

    vendor, asn = _check_asn(ip)
    if vendor:
        return {"is_scanner": True, "vendor": vendor, "confidence": "high",
                "reason": f"ip belongs to {vendor} (AS{asn})"}

    vendor, ua_reason = _check_user_agent(user_agent)
    if vendor:
        return {"is_scanner": True, "vendor": vendor, "confidence": "medium",
                "reason": f"user-agent matches {vendor} ({ua_reason})"}
    if ua_reason == "generic-bot-token":
        return {"is_scanner": False, "vendor": None, "confidence": "low",
                "reason": "user-agent has a generic bot/crawler token"}

    return {"is_scanner": False, "vendor": None, "confidence": None, "reason": ""}
