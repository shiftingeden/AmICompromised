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

## Status (2026-10-25)

**Everything is in App Store Connect for 1.0, build 6, iOS and macOS (build 6
attached on both; description and review notes updated). Nothing has been
submitted for review.** iOS build 6 is in TestFlight for the internal group
"Friends and I". Full Mac build 1.0 (6) is notarized and published as GitHub
release v1.0-6.

Done: engine + tests, iPhone app, Share action, shiny Navy/Orange/Gold icons,
Mac app (App Store + full), tip jar with themes and supporter icons, Contact
section, website (docs/), store text, screenshots (iPhone 6.3", iPad 13",
Mac), App Privacy, age rating, pricing (free) and availability.

## Added 2026-10-25 (build 6, uploaded and attached)

- **Widget** (`StatusWidget/`): small/medium Home Screen and lock-screen
  widget; status from `SharedStatus` in the App Group; tap = Scan Now via
  `amicompromised://scan`; days since restart + reminder.
- **Background protection** (`App/BackgroundMonitor.swift`, Protection
  screen): opt-in BGAppRefreshTask; refreshes lists, re-checks saved traces
  (`TraceSet`, recorded during every real log scan), warns about new
  exploited bugs, restart reminders. Alerts are time-sensitive with
  "Cut connections" (runs the user's "Am I Compromised Emergency" Shortcut
  via shortcuts://) and "Not now". iOS can't toggle Airplane Mode itself.
- Review notes, description and privacy policy updated for these.
- Untested on a real device: widget appearance (Simulator gallery blank),
  BG task timing, notification buttons, the Shortcut run.

## Added 2026-10-25 (build 7, uploaded and attached on iOS and macOS; store text updated)

- Home Screen name is now **Compromised?** (`CFBundleDisplayName`); the
  store name stays "Am I Compromised?".
- Lock Screen widgets: rectangular (status, "Checked … ago", next background
  check countdown or restart due), inline, and a circular restart gauge.
- **Scan Now control** (iOS 18+, `ScanControl` in `StatusWidget/`) for the
  Lock Screen, Control Center and Action button, plus a Siri/Shortcuts action
  (`App/ScanShortcuts.swift`). Both run `Intents/ScanNowIntent.swift`, which
  opens the app and sets a one-shot `scanRequested` flag in the App Group.
- Background settings keys moved into `SharedStatus` so the widget can read
  them.

## Added 2026-10-26 (build 8, uploaded and attached on iOS and macOS; store text updated)

- Widget: new large size (all status lines, last scan, next background
  check, restart, Scan Now + Cut buttons); medium size gains a Cut button.
  Cut opens `amicompromised://cut`, which runs the emergency Shortcut.
- `CutConnectionsIntent` (Intents/): a Cut Connections control for the Lock
  Screen / Control Center / Action button (iOS 18+) and a Siri action.

Future ideas (more free sources: malicious sites, stalkerware, trackers, Mac malware) are in [ROADMAP.md](ROADMAP.md).

## Due next (Eden)

- [ ] Install build 6 from TestFlight and check the new features: add the
      widget (small, medium, lock screen), turn on Background checks, set up
      the "Am I Compromised Emergency" Shortcut and tap Test, and confirm
      alerts sound/vibrate with Cut connections / Not now buttons.
- [ ] Real-device checks (APP-REVIEW-CHECKLIST Part 0 and Part 3): five
      minutes on an iPhone **and an iPad**; Share action in Analytics Data; a
      real sysdiagnose scan; a sandbox tip against the real App Store product
      (scheme StoreKit Configuration = None) incl. Restore; Dark Mode and
      largest Dynamic Type.
- [ ] Mac: click through both builds; Full build Back Up and Scan with a real
      encrypted backup.
- [ ] Then **Add for Review** on iOS and macOS (one submission, one app at a
      time per the checklist). Tips go in with the version.
- [ ] Optional: China mainland may need an ICP filing; untick it in
      Availability if Apple asks.

## Housekeeping

- Commit and push every change to github.com/shiftingeden/AmICompromised.
- Changes to `Tools/generate_apple_kev.py` or the workflow must be copied to
  the AmICompromised-data repo too.
- Mac store screenshots: run the Debug `AmICompromisedMac` build with
  `SNAPSHOT_DIR=/private/tmp/...` set.
- Build output goes outside Documents (iCloud attributes break codesign).

## Mac (two builds, one codebase in `Mac/`)

| | `AmICompromisedMac` (App Store) | `AmICompromisedMacDirect` (GitHub) |
|---|---|---|
| Bundle ID | `com.techbitsmix.AmICompromised` (Universal Purchase with iOS) | `com.techbitsmix.AmICompromised.direct` |
| Sandbox | Yes | No (hardened runtime, notarized) |
| macOS exploited-bug check | ✓ | ✓ |
| This Mac | Running apps only | Settings (SIP, Gatekeeper, FileVault, firewall, Lockdown), all processes, startup items, profiles/MDM, system extensions, hosts file, crash logs |
| iPhone | Scan a backup folder you pick (no link to the outside download: App Review risk) | Plug in → back up (AppleMobileBackup) → scan; lists Finder backups (needs Full Disk Access) |
| Sysdiagnose / log folder scan | ✓ | ✓ |

## How to scan an iPhone from the Mac

- **Full version:** plug the iPhone in, open iPhone in the sidebar, click
  Back Up and Scan. Grant Full Disk Access the first time.
- **App Store version:** back up the iPhone in Finder (turn on Encrypt local
  backup), then iPhone › Choose Backup Folder.
- Run the `AmICompromisedMac` / `AmICompromisedMacDirect` scheme, not the
  iPhone scheme: the iPhone build no longer runs on Macs.
