import Foundation
import LocalAuthentication

/// An automatic check the app can make from inside its sandbox.
struct DeviceCheck: Identifiable {
    var id: String
    var title: String
    var status: CheckStatus
    var detail: String

    static func runAll() -> [DeviceCheck] {
        [passcode(), jailbreak()]
    }

    static func passcode() -> DeviceCheck {
        var error: NSError?
        let set = LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: &error)
        let missing = (error as? LAError)?.code == .passcodeNotSet
        return DeviceCheck(
            id: "passcode", title: "Passcode",
            status: set ? .good : (missing ? .alert : .unknown),
            detail: set
                ? "A passcode is set, so your data is encrypted when the phone is locked."
                : (missing
                    ? "No passcode is set. Anyone holding the phone can open it, and your data isn't fully encrypted. Set one in Settings › Face ID & Passcode."
                    : "The app couldn't tell whether a passcode is set."))
    }

    /// Traces common jailbreak tools leave. A jailbroken phone loses most of
    /// iOS's protections, whether the owner did it or someone else did.
    static func jailbreak() -> DeviceCheck {
        #if targetEnvironment(simulator)
        return DeviceCheck(id: "jailbreak", title: "Jailbreak signs", status: .info,
                           detail: "Not checked in the Simulator.")
        #else
        let paths = [
            "/Applications/Cydia.app", "/Applications/Sileo.app", "/Applications/Zebra.app",
            "/var/jb", "/var/binpack", "/private/var/lib/apt", "/etc/apt", "/usr/sbin/sshd",
            "/usr/bin/ssh", "/bin/bash", "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/usr/lib/libjailbreak.dylib", "/private/preboot/jb",
        ]
        var found = paths.filter { FileManager.default.fileExists(atPath: $0) }
        let probe = "/private/am-i-compromised-\(UUID().uuidString)"
        if (try? "x".write(toFile: probe, atomically: false, encoding: .utf8)) != nil {
            try? FileManager.default.removeItem(atPath: probe)
            found.append("Apps can write outside their sandbox")
        }
        return DeviceCheck(
            id: "jailbreak", title: "Jailbreak signs",
            status: found.isEmpty ? .good : .alert,
            detail: found.isEmpty
                ? "No signs of common jailbreak tools."
                : "Found signs of a jailbreak: \(found.joined(separator: ", ")). If you didn't jailbreak this phone yourself, treat it as compromised.")
        #endif
    }
}

/// Things iOS doesn't let apps read, which the person checks themselves.
struct ManualCheck: Identifiable {
    var id: String
    var title: String
    var path: String
    var why: String

    static let all: [ManualCheck] = [
        ManualCheck(id: "autoupdate", title: "Automatic updates are on",
                    path: "Settings › General › Software Update › Automatic Updates. Turn on everything, including Security Responses & System Files.",
                    why: "Most real attacks use bugs that already have a fix. Updating quickly closes them."),
        ManualCheck(id: "profiles", title: "No profiles you don't recognise",
                    path: "Settings › General › VPN & Device Management.",
                    why: "A configuration profile can route your traffic or install certificates. Remove any you didn't add and that your work or school didn't give you."),
        ManualCheck(id: "devices", title: "Only your devices on your Apple Account",
                    path: "Settings › [your name], then scroll to the device list.",
                    why: "An unknown device there can read your iCloud data, including messages and photos."),
        ManualCheck(id: "safetycheck", title: "Run Safety Check",
                    path: "Settings › Privacy & Security › Safety Check.",
                    why: "Shows who you share location, photos and other data with, and lets you stop sharing in one place."),
        ManualCheck(id: "stolen", title: "Stolen Device Protection is on",
                    path: "Settings › Face ID & Passcode › Stolen Device Protection.",
                    why: "Stops someone who learned your passcode from changing your Apple Account password straight away."),
        ManualCheck(id: "lockdown", title: "Lockdown Mode, if you might be targeted",
                    path: "Settings › Privacy & Security › Lockdown Mode.",
                    why: "Journalists, activists, lawyers and officials are the usual targets of mercenary spyware. Lockdown Mode blocks most of the ways it gets in."),
        ManualCheck(id: "restart", title: "Restart your phone regularly",
                    path: "Turn it off and on again, ideally daily if you might be targeted.",
                    why: "Many spyware implants live only in memory and are removed by a restart until the attacker reinfects the phone."),
    ]
}
