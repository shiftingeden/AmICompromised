#!/usr/bin/env python3
"""Builds Data/apple-kev.json: every CISA KEV entry that affects iPhone OS,
with the iOS version ranges NVD lists as vulnerable.

Run from the project folder:

    python3 Tools/generate_apple_kev.py [output path]

The app fetches the same file from the GitHub repo at launch and falls back to
the copy bundled in the build. Re-run and commit when CISA adds Apple entries.
"""
import json, sys, time, urllib.request

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = ("https://services.nvd.nist.gov/rest/json/cves/2.0?hasKev"
           "&virtualMatchString=cpe:2.3:o:apple:iphone_os&resultsPerPage=2000&startIndex={}")
OUT = sys.argv[1] if len(sys.argv) > 1 else "Data/apple-kev.json"


def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "AmICompromised-generator"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.load(r)


def ios_ranges(cve):
    ranges = []
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable") or ":apple:iphone_os:" not in m["criteria"]:
                    continue
                exact = m["criteria"].split(":")[5]
                r = {k: m[k] for k in ("versionStartIncluding", "versionStartExcluding",
                                       "versionEndIncluding", "versionEndExcluding") if k in m}
                if exact not in ("*", "-"):
                    r = {"versionStartIncluding": exact, "versionEndIncluding": exact}
                if r and r not in ranges:
                    ranges.append(r)
    return ranges


def main():
    kev = {v["cveID"]: v for v in get(KEV_URL)["vulnerabilities"]}
    entries, start = [], 0
    while True:
        page = get(NVD_URL.format(start))
        for item in page["vulnerabilities"]:
            cve = item["cve"]
            k = kev.get(cve["id"])
            if not k:
                continue
            entries.append({
                "cve": cve["id"],
                "name": k["vulnerabilityName"],
                "summary": k["shortDescription"],
                "dateAdded": k["dateAdded"],
                "ranges": ios_ranges(cve),
            })
        start += page["resultsPerPage"]
        if start >= page["totalResults"]:
            break
        time.sleep(6)  # NVD allows 5 requests per 30 s without a key
    entries.sort(key=lambda e: e["dateAdded"], reverse=True)
    try:
        with open(OUT) as f:
            if json.load(f)["entries"] == entries:
                print("No changes", file=sys.stderr)
                return
    except (OSError, ValueError, KeyError):
        pass
    out = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": ["CISA KEV", "NVD"],
        "entries": entries,
    }
    with open(OUT, "w") as f:
        json.dump(out, f, indent=1)
    print(f"{len(entries)} entries written to {OUT}", file=sys.stderr)


if __name__ == "__main__":
    main()
