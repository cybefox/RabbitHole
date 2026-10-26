#!/usr/bin/env python3
"""Refreshes data/scanner_ranges.json with published CIDR ranges for known
email-security scanners, so scanner_detect.py can do fast local IP matching
with no network call on the request path.

Sources:
  - Zscaler: each cloud publishes its hub/datacenter ranges as JSON
    (https://config.zscaler.com/api/<cloud>/cenr/json).
  - Microsoft: Exchange Online Protection / Safe Links fetch traffic comes
    from the same pool advertised in the SPF record for
    spf.protection.outlook.com — resolved recursively (ip4/ip6/include).

Run this periodically (e.g. a weekly cron job); it's an offline refresh, not
something the Flask app calls at request time.
"""
import ipaddress
import json
import os
import re
import sys

import requests
import dns.resolver

OUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "scanner_ranges.json")

ZSCALER_CLOUDS = [
    "zscaler.net", "zscalerone.net", "zscalertwo.net", "zscalerthree.net",
    "zscloud.net", "zscalerbeta.net", "zscalergov.net",
]

CIDR_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\b")


def _valid_networks(cidrs):
    out = []
    for c in cidrs:
        try:
            out.append(str(ipaddress.ip_network(c, strict=False)))
        except ValueError:
            continue
    return out


def fetch_zscaler():
    """Zscaler's JSON schema has shifted over time, so rather than depend on
    exact field names, pull any CIDR-shaped string out of the parsed JSON."""
    found = set()
    for cloud in ZSCALER_CLOUDS:
        url = f"https://config.zscaler.com/api/{cloud}/cenr/json"
        try:
            resp = requests.get(url, timeout=10)
            resp.raise_for_status()
        except requests.RequestException as e:
            print(f"  ! zscaler [{cloud}] fetch failed: {e}", file=sys.stderr)
            continue
        for match in CIDR_RE.findall(resp.text):
            found.add(match)
    return _valid_networks(found)


def _resolve_spf_includes(name, seen=None, depth=0):
    """Recursively walk SPF 'include:' mechanisms, collecting ip4/ip6 CIDRs."""
    if seen is None:
        seen = set()
    if name in seen or depth > 5:
        return set()
    seen.add(name)

    cidrs = set()
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=10)
    except Exception as e:
        print(f"  ! spf txt lookup failed for {name}: {e}", file=sys.stderr)
        return cidrs

    for rdata in answers:
        txt = b"".join(rdata.strings).decode("utf-8", "ignore")
        if "v=spf1" not in txt:
            continue
        for token in txt.split():
            if token.startswith("ip4:") or token.startswith("ip6:"):
                val = token.split(":", 1)[1]
                if "/" not in val:
                    val = val + ("/32" if ":" not in val else "/128")
                cidrs.add(val)
            elif token.startswith("include:"):
                cidrs |= _resolve_spf_includes(token.split(":", 1)[1], seen, depth + 1)
    return cidrs


def fetch_microsoft():
    cidrs = _resolve_spf_includes("spf.protection.outlook.com")
    return _valid_networks(cidrs)


def main():
    result = {}

    print("Fetching Zscaler cloud ranges...")
    zscaler = fetch_zscaler()
    if zscaler:
        result["zscaler"] = zscaler
        print(f"  {len(zscaler)} ranges")

    print("Resolving Microsoft EOP/Safe Links SPF chain...")
    microsoft = fetch_microsoft()
    if microsoft:
        result["microsoft"] = microsoft
        print(f"  {len(microsoft)} ranges")

    if not result:
        print("Nothing fetched — leaving existing data/scanner_ranges.json untouched.", file=sys.stderr)
        sys.exit(1)

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w") as f:
        json.dump(result, f, indent=2, sort_keys=True)
    print(f"Wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
