#if FULL_SCAN
import Foundation
import IOKit
import IOKit.usb
import Observation

/// Notices an iPhone or iPad plugged in over USB and backs it up with
/// Apple's own `AppleMobileBackup` tool, the one Finder uses. Direct build
/// only: the App Store sandbox can't run other programs.
@MainActor @Observable
final class DeviceWatcher {
    struct Device: Equatable {
        var name: String
        /// The USB serial number, which is the device's UDID (without the
        /// dash newer models have in their backup folder name).
        var serial: String

        var udid: String {
            serial.count == 24 ? "\(serial.prefix(8))-\(serial.dropFirst(8))" : serial
        }
    }

    var device: Device?
    var isBackingUp = false
    var backupLog = ""
    var backupFailed: String?

    private var timer: Timer?

    static let tool = "/Library/Apple/System/Library/PrivateFrameworks/MobileDevice.framework/Versions/A/AppleMobileDeviceHelper.app/Contents/Resources/AppleMobileBackup"

    static var canBackUp: Bool { FileManager.default.isExecutableFile(atPath: tool) }

    func start() {
        poll()
        timer = Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.poll() }
        }
    }

    private func poll() {
        let found = Self.connectedDevices().first
        if found != device { device = found }
    }

    static func connectedDevices() -> [Device] {
        var iterator: io_iterator_t = 0
        guard IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching("IOUSBHostDevice"), &iterator) == KERN_SUCCESS else {
            return []
        }
        defer { IOObjectRelease(iterator) }
        var out: [Device] = []
        while case let service = IOIteratorNext(iterator), service != 0 {
            defer { IOObjectRelease(service) }
            func property(_ key: String) -> Any? {
                IORegistryEntryCreateCFProperty(service, key as CFString, kCFAllocatorDefault, 0)?.takeRetainedValue()
            }
            guard (property("idVendor") as? Int) == 0x05AC,
                  let name = property("USB Product Name") as? String,
                  name.contains("iPhone") || name.contains("iPad"),
                  let serial = property("USB Serial Number") as? String else { continue }
            out.append(Device(name: name, serial: serial))
        }
        return out
    }

    /// Runs a backup and returns true on success. The phone may ask the
    /// person to tap Trust or enter their passcode.
    func backUp(_ device: Device) async -> Bool {
        isBackingUp = true
        backupFailed = nil
        backupLog = ""
        defer { isBackingUp = false }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: Self.tool)
        process.arguments = ["--backup", "--target", device.udid, "--no-pass-prompt"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let text = String(decoding: handle.availableData, as: UTF8.self)
            guard !text.isEmpty else { return }
            Task { @MainActor in
                guard let self else { return }
                self.backupLog = String((self.backupLog + text).suffix(4000))
            }
        }
        // The handler goes on before run() so a fast exit can't be missed.
        let status: Int32? = await withCheckedContinuation { continuation in
            process.terminationHandler = { continuation.resume(returning: $0.terminationStatus) }
            do {
                try process.run()
            } catch {
                process.terminationHandler = nil
                continuation.resume(returning: nil)
            }
        }
        pipe.fileHandleForReading.readabilityHandler = nil
        guard let status else {
            backupFailed = "Couldn't start Apple's backup tool. Back up from Finder instead."
            return false
        }
        if status != 0 {
            backupFailed = "The backup didn't finish. Unlock your iPhone, tap Trust if asked, and try again. You can also back up from Finder."
            return false
        }
        return true
    }
}
#endif
