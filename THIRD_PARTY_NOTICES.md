# Third-party data

**mvt-indicators** — `Packages/CompromiseKit/Sources/CompromiseKit/Resources/indicators.yaml`
is a copy of the index from https://github.com/mvt-project/mvt-indicators,
used as a fallback when the live index can't be downloaded. The STIX indicator
files it lists are downloaded at runtime from their own repositories and are
not redistributed here.

    MIT License
    Copyright (c) 2022 MVT

**CISA Known Exploited Vulnerabilities** and **NIST National Vulnerability
Database** — `apple-kev.json` is derived from both. US government works,
public domain.

**Optional extra lists** (off by default) — downloaded at runtime from
https://github.com/shiftingeden/AmICompromised-data, which builds them from:

- Amnesty International, https://github.com/AmnestyTech/investigations
  (published research indicators).
- The Citizen Lab, https://github.com/citizenlab/malware-indicators
  (published research indicators).
- AdFection indicator set, CC0 1.0 Universal (public domain), compiled by the
  Zero Breach Toolkit project, https://github.com/interplains/Zero-Breach-Toolkit
  (`iocs/LICENSE.md`), from research by The Citizen Lab
  (https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/)
  and Confiant
  (https://blog.confiant.com/p/adint-weaponized-ad-tech-for-zero-click-spyware-and-mass-identity-vacuuming).
  Attribution is not required under CC0 and is given here as thanks.
  Zero Breach Toolkit's software (Apache 2.0) is not used or redistributed.

`Packages/CompromiseKit/Sources/CompromiseKit/Resources/extra-indicators.yaml`
is a fallback copy of the extra-lists index (names and paths only).
