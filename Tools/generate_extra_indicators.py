#!/usr/bin/env python3
"""Builds the optional "extra lists" for Am I Compromised?.

These are published spyware indicators that mvt-indicators' index does not
list. The app only uses them when the person turns on "Extra lists
(unauthenticated)", which is off by default: some come from an anonymous
third-party project, and the older ones are reformatted by this script from
CSV or plain-text files rather than published as STIX by their authors.

Writes, into the output folder (default: the current folder):
  extra-indicators.yaml     an index in the same format as mvt-indicators'
  extra/<id>.stix2          one STIX 2.1 bundle per source

Standard library only. A source that fails to download keeps its previous file,
so one broken link never empties the list.

Usage: python3 generate_extra_indicators.py [OUTPUT_DIR]
"""

import csv
import hashlib
import io
import json
import os
import re
import sys
import urllib.request
import uuid

RAW = "https://raw.githubusercontent.com/"
DATA_REPO = ("shiftingeden", "AmICompromised-data", "main")
NAMESPACE = uuid.UUID("6f1c7a52-3b1e-4c43-9a51-6a1d0e6c2b7e")

# AdFection comes from an anonymous project created in Oct 2026, so it is
# pinned to one reviewed commit and checksum instead of following its main
# branch. To take a newer version: review the diff, then update both values.
ADFECTION_COMMIT = "fe3ad460e99c436b41921047bd0d0d274a4180cd"
ADFECTION_SHA256 = "b346ad6fa1be58172847a5efca8567abb92428bd5359e9150922c37d1567c745"
# Its "historical / secondary" domains may have expired or changed hands, and
# its IPs are mostly reassigned cloud hosts; neither is used.
ADFECTION_TIERS = {"tier:delivery", "tier:cc", "tier:candiru", "tier:validator", "tier:historical"}

SOURCES = [
    # id, display name, kind, path under raw.githubusercontent.com
    ("adfection-2026",
     "AdFection ad-tech spyware delivery (Citizen Lab, Confiant 2026; via Zero Breach Toolkit, unverified)",
     "adfection",
     f"interplains/Zero-Breach-Toolkit/{ADFECTION_COMMIT}/dist/adfection.stix.json"),
    ("amnesty-cytrox-2021", "Cytrox Predator (Amnesty International 2021)", "stix2",
     "AmnestyTech/investigations/master/2021-12-16_cytrox/cytrox.stix2"),
    ("amnesty-nso-2018", "NSO Group Pegasus (Amnesty International 2018)", "csv-domain",
     "AmnestyTech/investigations/master/2018-08-01_nso/indicators.csv"),
    ("amnesty-nso-morocco-2019", "NSO Group Pegasus, Morocco (Amnesty International 2019)", "domains-txt",
     "AmnestyTech/investigations/master/2019-10-10_nso_morocco/domains.txt"),
    ("amnesty-finfisher-2020", "FinFisher FinSpy (Amnesty International 2020)", "domains-txt",
     "AmnestyTech/investigations/master/2020-09-25_finfisher/domains.txt"),
    ("citizenlab-nso-2016", "NSO Group Trident (Citizen Lab 2016)", "misp-csv",
     "citizenlab/malware-indicators/master/201608_NSO_Group/iocs.csv"),
    ("citizenlab-nso-mexico-exploit-2017", "NSO Group, Reckless Exploit (Citizen Lab 2017)", "misp-csv",
     "citizenlab/malware-indicators/master/201706_RecklessExploit/iocs.csv"),
    ("citizenlab-nso-mexico-redux-2017", "NSO Group, Reckless Redux (Citizen Lab 2017)", "misp-csv",
     "citizenlab/malware-indicators/master/201706_RecklessRedux/iocs.csv"),
    ("citizenlab-nso-insider-2017", "NSO Group, Insider Information (Citizen Lab 2017)", "misp-csv",
     "citizenlab/malware-indicators/master/201707_InsiderInfo/indicators.csv"),
    ("citizenlab-cyberbit-2017", "Cyberbit (Citizen Lab 2017)", "misp-csv",
     "citizenlab/malware-indicators/master/201712_Cyberbit/iocs.csv"),
    ("citizenlab-kingdom-2018", "NSO Group, The Kingdom Came to Canada (Citizen Lab 2018)", "misp-csv",
     "citizenlab/malware-indicators/master/201810_TheKingdomCameToCanada/iocs.csv"),
]

DOMAIN = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def fetch(path):
    req = urllib.request.Request(RAW + path, headers={"User-Agent": "AmICompromised-data"})
    with urllib.request.urlopen(req, timeout=60) as r:
        if r.status != 200:
            raise IOError(f"HTTP {r.status}")
        return r.read()


def clean_domain(value):
    v = value.strip().strip('"').lower().rstrip(".")
    v = v.replace("[.]", ".")
    if v.startswith("*."):
        v = v[2:]
    return v if DOMAIN.match(v) and not IPV4.match(v) else None


def indicator(source_id, kind, value):
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--" + str(uuid.uuid5(NAMESPACE, f"{source_id}|{kind}|{value}")),
        "created": "2026-10-27T00:00:00.000Z",
        "modified": "2026-10-27T00:00:00.000Z",
        "indicator_types": ["malicious-activity"],
        "pattern": f"[{kind} = '{escaped}']",
        "pattern_type": "stix",
        "valid_from": "2026-10-27T00:00:00.000Z",
    }


def bundle(source_id, items):
    """items: iterable of (stix kind, value); deduplicated and sorted."""
    unique = sorted(set(items))
    return {
        "type": "bundle",
        "id": "bundle--" + str(uuid.uuid5(NAMESPACE, source_id)),
        "objects": [indicator(source_id, k, v) for k, v in unique],
    }


def domains_only(values):
    return [("domain-name:value", d) for d in (clean_domain(v) for v in values) if d]


def build(source_id, kind, data):
    text = data.decode("utf-8", errors="replace")
    if kind == "adfection":
        digest = hashlib.sha256(data).hexdigest()
        if digest != ADFECTION_SHA256:
            raise ValueError(f"checksum mismatch {digest}")
        doc = json.loads(text)
        keep = []
        for o in doc.get("objects", []):
            if o.get("type") != "indicator":
                continue
            labels = set(o.get("labels", []))
            if "confidence:primary" not in labels or not (labels & ADFECTION_TIERS):
                continue
            m = re.match(r"\[domain-name:value\s*=\s*'([^']+)'\]$", o.get("pattern", ""))
            if m:
                keep.append(m.group(1))
        return bundle(source_id, domains_only(keep))
    if kind == "stix2":
        doc = json.loads(text)
        if not any(o.get("type") == "indicator" for o in doc.get("objects", [])):
            raise ValueError("no indicators")
        return doc  # published as STIX by its authors; passed through unchanged
    if kind == "domains-txt":
        lines = [l for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#")]
        return bundle(source_id, domains_only(lines))
    if kind == "csv-domain":
        rows = csv.DictReader(io.StringIO(text))
        return bundle(source_id, domains_only(r.get("domain_name", "") for r in rows))
    if kind == "misp-csv":
        items = []
        for r in csv.DictReader(io.StringIO(text)):
            t, v = (r.get("type") or "").strip(), (r.get("value") or "").strip()
            if t in ("domain", "hostname"):
                items += domains_only([v])
            elif t == "url" and v.startswith(("http://", "https://")):
                items.append(("url:value", v))
            elif t in ("email", "email-src", "email-dst") and "@" in v:
                items.append(("email-addr:value", v.lower()))
        return bundle(source_id, items)
    raise ValueError(f"unknown kind {kind}")


def count(doc):
    return sum(1 for o in doc.get("objects", []) if o.get("type") == "indicator")


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    os.makedirs(os.path.join(out, "extra"), exist_ok=True)
    owner, repo, branch = DATA_REPO
    index = ["# Optional extra lists for Am I Compromised? (off by default in the app).",
             "# Generated by generate_extra_indicators.py; same layout as mvt-indicators' indicators.yaml.",
             "indicators:"]
    failures = 0
    for source_id, name, kind, path in SOURCES:
        target = os.path.join(out, "extra", source_id + ".stix2")
        try:
            doc = build(source_id, kind, fetch(path))
            if count(doc) == 0:
                raise ValueError("empty")
            with open(target, "w") as f:
                json.dump(doc, f, indent=1, sort_keys=True)
                f.write("\n")
            print(f"{source_id}: {count(doc)} indicators")
        except Exception as e:  # keep the previous file
            failures += 1
            print(f"{source_id}: FAILED ({e}); keeping previous file", file=sys.stderr)
        if os.path.exists(target):
            index += ["  -", f"    name: {name}", f"    type: github", "    github:",
                      f"      owner: {owner}", f"      repo: {repo}", f"      branch: {branch}",
                      f"      path: extra/{source_id}.stix2"]
    with open(os.path.join(out, "extra-indicators.yaml"), "w") as f:
        f.write("\n".join(index) + "\n")
    return 1 if failures == len(SOURCES) else 0


if __name__ == "__main__":
    sys.exit(main())
