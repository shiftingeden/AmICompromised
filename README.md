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

## Status (2026-10-24)

Done: CompromiseKit engine + tests (iOS/macOS exploited-bug catalog, STIX
matching, sysdiagnose scanner, Mac system scanner, encrypted iPhone backup
scanner), iPhone app (Scan Now, device checks, guided sysdiagnose flow,
"Scan for Spyware" Share action), app icon, Mac app in two builds, public
data repo with daily Action, public source repo (MIT).

**Pricing:** free everywhere, with a tip jar (IAP to donate) that unlocks
supporter extras such as accent colour themes. No scan limits, no paywall.

## Due next

**Test on a real iPhone:**
- [ ] "Scan for Spyware" shows in Analytics Data's Share sheet with the
      shield glyph (the Simulator shows a placeholder icon), and the scan
      starts when the app opens.
- [ ] Pressing the sysdiagnose buttons on the scan screen ticks step 1.
- [ ] Scan time and memory on a real ~300 MB sysdiagnose; false positives
      on a clean phone.

**Test the Mac app:**
- [ ] Click through both builds (`Am I Compromised` = App Store,
      `Am I Compromised Full` = direct download).
- [ ] Full build: grant Full Disk Access, plug in an iPhone, Back Up and
      Scan (uses Apple's `AppleMobileBackup`), then scan an encrypted backup
      with its password. Decryption is only tested on synthetic backups.
- [ ] App Store build: choosing the MobileSync backup folder in the open
      panel actually grants read access under the sandbox.

**Build:**
- [x] Tip jar (StoreKit 2) on iPhone and Mac App Store build, with seven
      colour themes (Ocean free, six unlocked by any tip). Full Mac build
      unlocks themes and points to the App Store versions for tipping.
- [ ] Create the four consumables in App Store Connect with the IDs in
      `Shared/TipJar.swift` (tip.small/medium/large/huge at 0.99 / 2.99 /
      4.99 / 9.99), then try a tip by running from Xcode (the scheme uses
      `Config/AmICompromised.storekit`). `xcodebuild test` skips the purchase
      test because it gets no StoreKit test environment here.
- [ ] Privacy policy + support page (GitHub Pages).
- [ ] App Store copy ("known threats", never "antivirus"/"zero-day
      detection"), review notes, screenshots, `app.json`.
- [ ] Notarize the Full build and publish it as a GitHub release (the App
      Store build's "Get the full version" link points there).

**Housekeeping:**
- Commit and push every change to github.com/shiftingeden/AmICompromised.
- Changes to `Tools/generate_apple_kev.py` or the workflow must be copied to
  the AmICompromised-data repo too.

## Mac (two builds, one codebase in `Mac/`)

| | `AmICompromisedMac` (App Store) | `AmICompromisedMacDirect` (GitHub) |
|---|---|---|
| Bundle ID | `com.techbitsmix.AmICompromised` (Universal Purchase with iOS) | `com.techbitsmix.AmICompromised.direct` |
| Sandbox | Yes | No (hardened runtime, notarized) |
| macOS exploited-bug check | ✓ | ✓ |
| This Mac | Running apps only | Settings (SIP, Gatekeeper, FileVault, firewall, Lockdown), all processes, startup items, profiles/MDM, system extensions, hosts file, crash logs |
| iPhone | Scan a backup folder you pick | Plug in → back up (AppleMobileBackup) → scan; lists Finder backups (needs Full Disk Access) |
| Sysdiagnose / log folder scan | ✓ | ✓ |
