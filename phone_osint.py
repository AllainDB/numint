#!/usr/bin/env python3
"""
phone_osint.py — Phone number intelligence tool

Gathers legitimate, accurate signals on a phone number:
  - validation, region, carrier, timezones, line type (offline, no key)
  - optional live carrier/line-type via Numverify (set NUMVERIFY_API_KEY)
  - a heuristic scam-likelihood note (clearly labeled, not authoritative)
  - Google footprint search URLs (dorks) you open manually

Uses only public/legitimate data. Does NOT scrape breached data or PII brokers.

Usage:
  python3 phone_osint.py "+13055551234"
  python3 phone_osint.py "305-555-1234" --region US
  python3 phone_osint.py "+447911123456" --json
"""

import argparse
import json
import os
import sys
import urllib.parse
import urllib.request

import phonenumbers
from phonenumbers import carrier, geocoder, timezone
from phonenumbers import PhoneNumberType

NUMBER_TYPES = {
    PhoneNumberType.MOBILE: "mobile",
    PhoneNumberType.FIXED_LINE: "fixed line",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed line or mobile",
    PhoneNumberType.TOLL_FREE: "toll-free",
    PhoneNumberType.PREMIUM_RATE: "premium rate",
    PhoneNumberType.SHARED_COST: "shared cost",
    PhoneNumberType.VOIP: "VOIP",
    PhoneNumberType.PERSONAL_NUMBER: "personal number",
    PhoneNumberType.PAGER: "pager",
    PhoneNumberType.UAN: "UAN",
    PhoneNumberType.VOICEMAIL: "voicemail",
    PhoneNumberType.UNKNOWN: "unknown",
}


def base_lookup(raw, region):
    """Offline lookup via libphonenumber. No network, no API key."""
    parsed = phonenumbers.parse(raw, region)
    valid = phonenumbers.is_valid_number(parsed)
    possible = phonenumbers.is_possible_number(parsed)
    ntype = phonenumbers.number_type(parsed)

    return {
        "input": raw,
        "valid": valid,
        "possible": possible,
        "e164": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
        "international": phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
        ),
        "national": phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.NATIONAL
        ),
        "country_code": parsed.country_code,
        "region": geocoder.description_for_number(parsed, "en") or "unknown",
        "carrier": carrier.name_for_number(parsed, "en") or "unknown",
        "timezones": list(timezone.time_zones_for_number(parsed)),
        "line_type": NUMBER_TYPES.get(ntype, "unknown"),
        "_parsed": parsed,
    }


def numverify_lookup(e164):
    """Optional live lookup. Returns None if no key set or request fails."""
    key = os.environ.get("NUMVERIFY_API_KEY")
    if not key:
        return None
    url = "https://apilayer.net/api/validate?" + urllib.parse.urlencode(
        {"access_key": key, "number": e164.lstrip("+")}
    )
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.loads(resp.read().decode())
        if not data.get("valid", True) and "error" in data:
            return {"error": data["error"].get("info", "lookup failed")}
        return {
            "valid": data.get("valid"),
            "carrier": data.get("carrier") or "unknown",
            "line_type": data.get("line_type") or "unknown",
            "location": data.get("location") or "unknown",
            "country": data.get("country_name") or "unknown",
        }
    except Exception as e:
        return {"error": str(e)}


def scam_signals(base, live):
    """Heuristic flags. NOT authoritative — these raise suspicion, not proof."""
    flags = []
    line = (live or {}).get("line_type") or base["line_type"]
    line = str(line).lower()

    if "voip" in line:
        flags.append("VOIP line — heavily favored by scammers (burner/disposable)")
    if not base["valid"]:
        flags.append("Number fails validation — malformed or spoofed format")
    if "premium" in line:
        flags.append("Premium-rate number — charges on contact")
    if "toll-free" in line:
        flags.append("Toll-free — common for spoofed callbacks")
    if base["carrier"] == "unknown" and "mobile" not in line:
        flags.append("No carrier resolved — often the case for VOIP/spoofed numbers")

    level = "LOW"
    if any("VOIP" in f or "validation" in f for f in flags):
        level = "ELEVATED"
    if len(flags) >= 2:
        level = "HIGH"
    return level, flags


def footprint_urls(e164, national):
    """Google search URLs to check public footprint. You open these manually."""
    digits = e164.lstrip("+")
    queries = [
        f'"{e164}"',
        f'"{national}"',
        f'"{digits}" (scam OR spam OR fraud OR complaint)',
        f'"{e164}" site:reddit.com',
        f'"{national}" site:whocallsme.com OR site:800notes.com',
    ]
    return [
        "https://www.google.com/search?q=" + urllib.parse.quote(q) for q in queries
    ]


def report(base, live, level, flags, urls):
    line = "=" * 56
    print(line)
    print(f"  PHONE INTELLIGENCE REPORT")
    print(line)
    print(f"  Input            : {base['input']}")
    print(f"  E.164            : {base['e164']}")
    print(f"  International     : {base['international']}")
    print(f"  National         : {base['national']}")
    print(f"  Valid            : {base['valid']}  (possible: {base['possible']})")
    print(f"  Region           : {base['region']}")
    print(f"  Carrier (offline): {base['carrier']}")
    print(f"  Line type        : {base['line_type']}")
    print(f"  Timezone(s)      : {', '.join(base['timezones']) or 'unknown'}")

    if live:
        print(line)
        if "error" in live:
            print(f"  Numverify        : error — {live['error']}")
        else:
            print(f"  Carrier (live)   : {live['carrier']}")
            print(f"  Line type (live) : {live['line_type']}")
            print(f"  Location (live)  : {live['location']}")
    else:
        print(line)
        print("  Numverify        : skipped (set NUMVERIFY_API_KEY for live data)")

    print(line)
    print(f"  SCAM HEURISTIC   : {level}")
    if flags:
        for f in flags:
            print(f"    - {f}")
    else:
        print("    - no automatic flags raised")
    print("  (heuristic only — raises suspicion, does not prove intent)")

    print(line)
    print("  FOOTPRINT SEARCHES (open manually):")
    for u in urls:
        print(f"    {u}")
    print(line)


def main():
    ap = argparse.ArgumentParser(description="Phone number intelligence tool")
    ap.add_argument("number", help="phone number (E.164 e.g. +13055551234, or local with --region)")
    ap.add_argument("--region", default=None, help="2-letter region code (e.g. US) for local-format numbers")
    ap.add_argument("--json", action="store_true", help="output JSON instead of a report")
    args = ap.parse_args()

    try:
        base = base_lookup(args.number, args.region)
    except phonenumbers.NumberParseException as e:
        print(f"Could not parse number: {e}", file=sys.stderr)
        print("Tip: use E.164 (+countrycode...) or pass --region US", file=sys.stderr)
        sys.exit(1)

    live = numverify_lookup(base["e164"])
    level, flags = scam_signals(base, live)
    urls = footprint_urls(base["e164"], base["national"])

    if args.json:
        base.pop("_parsed", None)
        print(json.dumps(
            {"base": base, "numverify": live, "scam_level": level,
             "scam_flags": flags, "footprint_urls": urls},
            indent=2,
        ))
    else:
        report(base, live, level, flags, urls)


if __name__ == "__main__":
    main()
