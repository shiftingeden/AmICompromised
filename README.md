# Am I Compromised?

One app for iPhone, iPad and (v2) Mac that checks for **known** traces of
mercenary spyware and stalkerware. It never claims a phone is clean: new
spyware has no public indicators until researchers catch it.

Everything runs on the device. The app downloads public indicator lists
(Amnesty International, Citizen Lab, iVerify and others, via
[mvt-indicators](https://github.com/mvt-project/mvt-indicators)) and the
exploited-bug catalog from
[AmICompromised-data](https://github.com/shiftingeden/AmICompromised-data);
it never uploads logs or results.

Issues and pull requests are welcome, especially new checks and false-positive
reports. MIT licensed; see `LICENSE` and `THIRD_PARTY_NOTICES.md`.

    xcodegen generate && open AmICompromised.xcodeproj

Bundle ID `com.techbitsmix.AmICompromised`, team XNGW97HPY6, iOS 17+.

## Layout

| Path | What |
|---|---|
| `Packages/CompromiseKit` | Detection engine shared by iPhone and Mac. No UI. |
| `App/` | SwiftUI app (iPhone/iPad Quick Scan). |
| `Tools/generate_apple_kev.py` | Builds `Data/apple-kev.json` from CISA KEV + NVD. |
| `Tools/data-repo/` | GitHub Action for the public data repo that keeps the catalog fresh. |

## Quick Scan (v1, iPhone)

1. **Software update check.** iOS version vs CISA's Known Exploited
   Vulnerabilities, with fixed versions from NVD. Fetched from
   `DataStore.catalogURL`; falls back to the copy bundled in the build.
2. **Device checks.** Passcode set, jailbreak traces, plus a manual checklist
   for what iOS doesn't let apps read (profiles, Lockdown Mode, devices…).
3. **Spyware log scan.** The user shares a sysdiagnose (.tar.gz) to the app.
   CompromiseKit streams it (gzip + tar, no full extraction) and matches it
   against every STIX2 file listed in mvt-indicators' `indicators.yaml`:
   domains, process names (ps.txt, shutdown.log, crash log names), file paths,
   profile IDs, app IDs, emails. Also flags processes at shutdown running
   from `/private/var/db` or `/private/var/tmp` (Kaspersky iShutdown method).

Indicator lists are downloaded at launch (every 12 h) and cached, so new
campaigns are picked up with no app update.

## Tests

The Documents folder adds Finder attributes that break code signing, so build
outside it:

    cd Packages/CompromiseKit
    swift test --scratch-path /tmp/ck-build
    LIVE=1 swift test --scratch-path /tmp/ck-build --filter LiveTests   # hits GitHub

## To do before submission

- [x] Public data repo https://github.com/shiftingeden/AmICompromised-data
      (created 2026-10-23). Daily Action regenerates `apple-kev.json`; commits
      only when the bug list changes. Copy script/workflow changes from
      `Tools/` there by hand.
- [ ] App icon (`App/Assets.xcassets/AppIcon.appiconset` is empty).
- [ ] Test the share-sheet flow with a real sysdiagnose on a device (Simulator
      can't make one); check scan time and memory on a ~300 MB archive.
- [ ] Privacy policy + support page; App Store copy that says "known
      threats", never "antivirus" or "zero-day detection".
- [ ] Decide IAP (scan limits / Mac Thorough Scan).

## v2: Mac Thorough Scan

Add a macOS destination to the same target (Universal Purchase). The Mac side
opens an encrypted Finder backup (user picks the folder), decrypts it with
the backup password, and runs MVT's backup checks in Swift on top of
CompromiseKit's indicator matching. `SysdiagnoseScanner` already accepts an
extracted folder.
