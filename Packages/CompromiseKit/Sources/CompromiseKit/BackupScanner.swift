import CommonCrypto
import Foundation
import SQLite3

public enum BackupError: LocalizedError {
    case notABackup, needsPassword, wrongPassword, unreadable(String)

    public var errorDescription: String? {
        switch self {
        case .notABackup: "This folder isn't an iPhone backup. Choose the folder that contains Manifest.db."
        case .needsPassword: "This backup is encrypted. Enter the backup password you set in Finder."
        case .wrongPassword: "That password didn't unlock the backup. It's the backup password from Finder, not your iPhone passcode."
        case .unreadable(let why): "Couldn't read the backup: \(why)"
        }
    }
}

/// What a backup says about the phone it came from.
public struct BackupInfo: Codable, Hashable, Sendable {
    public var folder: URL
    public var deviceName: String
    public var productType: String
    public var iOSVersion: String
    public var lastBackup: Date?
    public var isEncrypted: Bool
    public var udid: String

    public init(folder: URL) throws {
        let info = (NSDictionary(contentsOf: folder.appendingPathComponent("Info.plist")) as? [String: Any]) ?? [:]
        guard let manifest = NSDictionary(contentsOf: folder.appendingPathComponent("Manifest.plist")) as? [String: Any],
              FileManager.default.fileExists(atPath: folder.appendingPathComponent("Manifest.db").path) else {
            throw BackupError.notABackup
        }
        let lockdown = manifest["Lockdown"] as? [String: Any] ?? [:]
        self.folder = folder
        deviceName = info["Device Name"] as? String ?? lockdown["DeviceName"] as? String ?? "iPhone"
        productType = info["Product Type"] as? String ?? lockdown["ProductType"] as? String ?? ""
        iOSVersion = info["Product Version"] as? String ?? lockdown["ProductVersion"] as? String ?? ""
        lastBackup = info["Last Backup Date"] as? Date ?? manifest["Date"] as? Date
        isEncrypted = manifest["IsEncrypted"] as? Bool ?? false
        udid = info["Unique Identifier"] as? String ?? lockdown["UniqueDeviceID"] as? String ?? folder.lastPathComponent
    }

    /// Backups Finder made on this Mac, newest first. Reading the folder
    /// needs Full Disk Access; without it this throws.
    public static func finderBackups() throws -> [BackupInfo] {
        let root = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/MobileSync/Backup", isDirectory: true)
        let folders = try FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil)
        return folders.compactMap { try? BackupInfo(folder: $0) }
            .sorted { ($0.lastBackup ?? .distantPast) > ($1.lastBackup ?? .distantPast) }
    }
}

public struct BackupScanReport: Codable, Sendable {
    public var device: BackupInfo
    public var scannedAt: Date
    public var findings: [Finding]
    /// What was looked at, e.g. "Safari history: 2,410 visits".
    public var coverage: [String]
    public var indicatorCount: Int

    public var matches: [Finding] { findings.filter { $0.level == .match } }
}

/// Scans an iTunes/Finder backup the way MVT's backup modules do: installed
/// apps, messages, browser history, data usage and configuration profiles,
/// all matched against the indicator lists.
public final class BackupScanner {
    let info: BackupInfo
    let scanner: LogScanner
    let indicatorCount: Int
    private var keybag: Keybag?
    private let manifestDB: URL
    private let temp: URL

    /// Opens the backup. Encrypted backups need `password` (the one set in
    /// Finder); it's only used here, in memory, and never stored.
    public init(info: BackupInfo, indicators: IndicatorSet, password: String?) throws {
        self.info = info
        scanner = LogScanner(indicators: indicators)
        indicatorCount = indicators.total
        temp = FileManager.default.temporaryDirectory.appendingPathComponent("backup-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: temp, withIntermediateDirectories: true)

        let source = info.folder.appendingPathComponent("Manifest.db")
        guard info.isEncrypted else { manifestDB = source; return }
        guard let password, !password.isEmpty else { throw BackupError.needsPassword }
        guard let manifest = NSDictionary(contentsOf: info.folder.appendingPathComponent("Manifest.plist")) as? [String: Any],
              let bagData = manifest["BackupKeyBag"] as? Data,
              let manifestKey = manifest["ManifestKey"] as? Data else { throw BackupError.unreadable("missing keybag") }
        let bag = try Keybag(bagData)
        try bag.unlock(password: password)
        keybag = bag
        let key = try bag.unwrapFileKey(manifestKey)
        let plain = try Crypto.aesCBCDecrypt(Data(contentsOf: source), key: key)
        manifestDB = temp.appendingPathComponent("Manifest.db")
        try plain.write(to: manifestDB)
        guard (try? SQLiteDB(manifestDB).rows("SELECT count(*) FROM Files")) != nil else {
            throw BackupError.wrongPassword
        }
    }

    deinit { try? FileManager.default.removeItem(at: temp) }

    struct Target {
        var label: String
        var domain: String
        var path: String
        /// SQL whose columns are scanned as text, or nil for a plist.
        var query: String?
        var processColumns = false
    }

    static let targets: [Target] = [
        Target(label: "Messages", domain: "HomeDomain", path: "Library/SMS/sms.db",
               query: "SELECT text FROM message WHERE text IS NOT NULL"),
        Target(label: "Safari history", domain: "HomeDomain", path: "Library/Safari/History.db",
               query: "SELECT url FROM history_items"),
        Target(label: "Chrome history", domain: "AppDomain-com.google.chrome.ios",
               path: "Library/Application Support/Google/Chrome/Default/History", query: "SELECT url FROM urls"),
        Target(label: "WhatsApp messages", domain: "AppDomainGroup-group.net.whatsapp.WhatsApp.shared",
               path: "ChatStorage.sqlite", query: "SELECT ZTEXT FROM ZWAMESSAGE WHERE ZTEXT IS NOT NULL"),
        Target(label: "Data usage", domain: "WirelessDomain", path: "Library/Databases/DataUsage.sqlite",
               query: "SELECT ZPROCNAME, ZBUNDLENAME FROM ZPROCESS", processColumns: true),
        Target(label: "Network usage", domain: "WirelessDomain", path: "Library/Databases/netusage.sqlite",
               query: "SELECT ZPROCNAME, ZBUNDLENAME FROM ZPROCESS", processColumns: true),
        Target(label: "Analytics", domain: "HomeDomain", path: "Library/Preferences/com.apple.osanalytics.addaily.plist"),
    ]

    public func scan(progress: @Sendable (Double, String) -> Void = { _, _ in }) throws -> BackupScanReport {
        var findings: [Finding] = []
        var coverage: [String] = []
        let db = try SQLiteDB(manifestDB)

        // Installed apps, from the manifest's app domains.
        progress(0.05, "Installed apps")
        let domains = try db.rows("SELECT DISTINCT domain FROM Files").compactMap { $0.first ?? nil }
        let apps = Set(domains.compactMap { d -> String? in
            for prefix in ["AppDomain-", "AppDomainGroup-", "AppDomainPlugin-"] where d.hasPrefix(prefix) {
                return String(d.dropFirst(prefix.count))
            }
            return nil
        })
        var appFindings = Findings(file: "Installed apps")
        for app in apps.sorted() {
            if let c = scanner.campaign(forApp: app) {
                appFindings.add(.match, "Installed app", app, c, "An app with this ID is listed as spyware or stalkerware.")
            }
        }
        findings += appFindings.items
        coverage.append("Installed apps: \(apps.count)")

        // File names and paths in the backup.
        progress(0.15, "Files in the backup")
        var pathFindings = Findings(file: "Backup manifest")
        let files = try db.rows("SELECT domain, relativePath FROM Files")
        for row in files {
            guard let path = row[1] else { continue }
            let name = (path as NSString).lastPathComponent
            if let c = scanner.campaign(forPath: "/private/var/mobile/" + path) ?? scanner.campaign(forPath: path) {
                pathFindings.add(.match, "File in backup", "\(row[0] ?? "")/\(path)", c, "The backup contains a file at a path listed as a trace of this spyware.")
            } else if !name.isEmpty, let c = scanner.campaign(forProcess: name), name.count > 3 {
                pathFindings.add(.match, "File in backup", "\(row[0] ?? "")/\(path)", c, "A file in the backup is named like this spyware's components.")
            }
        }
        findings += pathFindings.items
        coverage.append("Files in backup: \(files.count)")

        // Configuration profiles: scan every profile file as text so their
        // UUIDs and payload domains get matched.
        progress(0.25, "Configuration profiles")
        let profileRows = try db.rows(
            "SELECT fileID, relativePath, file FROM Files WHERE domain = 'SysSharedContainerDomain-systemgroup.com.apple.configurationprofiles' AND flags = 1")
        var profileCount = 0
        for row in profileRows {
            guard let fileID = row[0], let path = row[1], let data = try? extract(fileID: fileID, meta: row[2]) else { continue }
            profileCount += 1
            findings += scanner.scan(path: "Profiles/" + path, data: Self.textForm(data))
        }
        coverage.append("Configuration profile files: \(profileCount)")

        for (i, target) in Self.targets.enumerated() {
            progress(0.3 + 0.65 * Double(i) / Double(Self.targets.count), target.label)
            guard let row = try db.rows(
                "SELECT fileID, file FROM Files WHERE domain = ? AND relativePath = ?", [target.domain, target.path]).first,
                  let fileID = row[0], let data = try? extract(fileID: fileID, meta: row[1]) else { continue }
            let (found, summary) = try scan(target, data: data)
            findings += found
            coverage.append("\(target.label): \(summary)")
        }
        progress(1, "Done")
        return BackupScanReport(device: info, scannedAt: Date(), findings: findings, coverage: coverage,
                                indicatorCount: indicatorCount)
    }

    private func scan(_ target: Target, data: Data) throws -> ([Finding], String) {
        guard let query = target.query else {
            // The analytics plist keys are process names that used the network.
            let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
            let names = (plist?["netUsageBaseline"] as? [String: Any])?.keys.map { $0 } ?? []
            var out = Findings(file: target.label)
            for name in names {
                if let c = scanner.campaign(forProcess: name) {
                    out.add(.match, "Process in analytics", name, c, "This process name, linked to this spyware, used the network.")
                }
            }
            return (out.items + scanner.scan(path: target.label, data: Self.textForm(data)), "\(names.count) processes")
        }
        let file = temp.appendingPathComponent(UUID().uuidString + ".sqlite")
        try data.write(to: file)
        defer { try? FileManager.default.removeItem(at: file) }
        let rows = try SQLiteDB(file).rows(query)
        if target.processColumns {
            var out = Findings(file: target.label)
            for row in rows {
                if let name = row[0], let c = scanner.campaign(forProcess: name) {
                    out.add(.match, "Process in \(target.label.lowercased())", name, c, "This process name, linked to this spyware, used mobile data or Wi-Fi.")
                }
                if let bundle = row.count > 1 ? row[1] : nil, let c = scanner.campaign(forApp: bundle) {
                    out.add(.match, "App in \(target.label.lowercased())", bundle, c, "This app ID, linked to spyware, used the network.")
                }
            }
            return (out.items, "\(rows.count) processes")
        }
        let text = rows.map { $0.compactMap { $0 }.joined(separator: " ") }.joined(separator: "\n")
        return (scanner.scan(path: target.label, data: Data(text.utf8)), "\(rows.count.formatted()) entries")
    }

    /// Binary plists hide their strings from the tokenizer; XML doesn't.
    static func textForm(_ data: Data) -> Data {
        guard data.starts(with: Data("bplist".utf8)),
              let object = try? PropertyListSerialization.propertyList(from: data, format: nil),
              let xml = try? PropertyListSerialization.data(fromPropertyList: object, format: .xml, options: 0)
        else { return data }
        return xml
    }

    /// A file's contents, decrypted if the backup is encrypted.
    func extract(fileID: String, meta: String?) throws -> Data {
        let url = info.folder.appendingPathComponent(String(fileID.prefix(2))).appendingPathComponent(fileID)
        let raw = try Data(contentsOf: url)
        guard let keybag else { return raw }
        guard let meta, let blob = Data(base64Encoded: meta),
              let (wrapped, size) = Self.fileKey(from: blob) else { throw BackupError.unreadable("no key for \(fileID)") }
        let plain = try Crypto.aesCBCDecrypt(raw, key: keybag.unwrapFileKey(wrapped))
        return size.map { plain.prefix($0) } ?? plain
    }

    /// Pulls EncryptionKey and Size out of the NSKeyedArchiver'd MBFile in
    /// Manifest.db's `file` column.
    static func fileKey(from blob: Data) -> (Data, Int?)? {
        guard let plist = try? PropertyListSerialization.propertyList(from: blob, format: nil) as? [String: Any],
              let objects = plist["$objects"] as? [Any] else { return nil }
        func resolve(_ value: Any?) -> Any? {
            guard let value else { return nil }
            // CF bridges archiver UIDs as an opaque type; its description is
            // "<CFKeyedArchiverUID ...>{value = N}".
            let text = String(describing: value)
            if text.contains("CFKeyedArchiverUID"), let r = text.range(of: "value = "),
               let n = Int(text[r.upperBound...].prefix { $0.isNumber }), n < objects.count {
                return objects[n]
            }
            return value
        }
        for case let dict as [String: Any] in objects where dict["EncryptionKey"] != nil {
            let keyObject = resolve(dict["EncryptionKey"])
            let key = (keyObject as? Data) ?? ((keyObject as? [String: Any])?["NS.data"] as? Data)
            let size = (resolve(dict["Size"]) as? NSNumber)?.intValue
            return key.map { ($0, size) }
        }
        return nil
    }
}

// MARK: - Keybag

/// The backup keybag from Manifest.plist: per-protection-class keys, wrapped
/// with a key derived from the backup password.
final class Keybag {
    private var attributes: [String: Data] = [:]
    private var classes: [UInt32: [String: Data]] = [:]
    private var classKeys: [UInt32: Data] = [:]

    init(_ data: Data) throws {
        var current: [String: Data]?
        var i = data.startIndex
        while i + 8 <= data.endIndex {
            let tag = String(decoding: data[i..<i + 4], as: UTF8.self)
            let length = Int(data[i + 4..<i + 8].reduce(0) { $0 << 8 | UInt32($1) })
            guard i + 8 + length <= data.endIndex else { throw BackupError.unreadable("bad keybag") }
            let value = Data(data[i + 8..<i + 8 + length])
            i += 8 + length
            if tag == "UUID" {
                if let c = current, let cls = c["CLAS"] { classes[Self.int(cls)] = c }
                // The first UUID belongs to the keybag itself.
                current = attributes["UUID"] == nil ? nil : [:]
                if current == nil { attributes["UUID"] = value } else { current?["UUID"] = value }
            } else if current != nil {
                current?[tag] = value
            } else {
                attributes[tag] = value
            }
        }
        if let c = current, let cls = c["CLAS"] { classes[Self.int(cls)] = c }
    }

    static func int(_ data: Data) -> UInt32 { data.reduce(0) { $0 << 8 | UInt32($1) } }

    func unlock(password: String) throws {
        guard let salt = attributes["SALT"], let iterData = attributes["ITER"] else {
            throw BackupError.unreadable("keybag has no salt")
        }
        var passcode = Data(password.utf8)
        if let dpsl = attributes["DPSL"], let dpic = attributes["DPIC"] {
            passcode = try Crypto.pbkdf2(passcode, salt: dpsl, rounds: Self.int(dpic), prf: CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256))
        }
        let key = try Crypto.pbkdf2(passcode, salt: salt, rounds: Self.int(iterData), prf: CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1))
        for (cls, entry) in classes {
            guard let wrap = entry["WRAP"], Self.int(wrap) & 2 != 0, let wpky = entry["WPKY"] else { continue }
            guard let unwrapped = Crypto.aesUnwrap(wpky, kek: key) else { throw BackupError.wrongPassword }
            classKeys[cls] = unwrapped
        }
        if classKeys.isEmpty { throw BackupError.wrongPassword }
    }

    /// A per-file (or manifest) key: 4-byte little-endian class, then the
    /// key wrapped with that class's key.
    func unwrapFileKey(_ blob: Data) throws -> Data {
        guard blob.count > 4 else { throw BackupError.unreadable("short key") }
        let cls = blob.prefix(4).reversed().reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        guard let classKey = classKeys[cls],
              let key = Crypto.aesUnwrap(Data(blob.dropFirst(4)), kek: classKey) else {
            throw BackupError.unreadable("no key for protection class \(cls)")
        }
        return key
    }
}

// MARK: - Crypto

enum Crypto {
    static func pbkdf2(_ password: Data, salt: Data, rounds: UInt32, prf: CCPseudoRandomAlgorithm) throws -> Data {
        var out = Data(count: 32)
        let status = out.withUnsafeMutableBytes { o in
            password.withUnsafeBytes { p in
                salt.withUnsafeBytes { s in
                    CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                         p.baseAddress?.assumingMemoryBound(to: CChar.self), password.count,
                                         s.baseAddress?.assumingMemoryBound(to: UInt8.self), salt.count,
                                         prf, rounds, o.baseAddress?.assumingMemoryBound(to: UInt8.self), 32)
                }
            }
        }
        guard status == kCCSuccess else { throw BackupError.unreadable("key derivation failed") }
        return out
    }

    /// RFC 3394 AES key unwrap. Returns nil when the integrity check fails,
    /// which is how a wrong password shows up.
    static func aesUnwrap(_ wrapped: Data, kek: Data) -> Data? {
        var outLength = CCSymmetricUnwrappedSize(CCWrappingAlgorithm(kCCWRAPAES), wrapped.count)
        var out = Data(count: outLength)
        let status = out.withUnsafeMutableBytes { o in
            wrapped.withUnsafeBytes { w in
                kek.withUnsafeBytes { k in
                    CCSymmetricKeyUnwrap(CCWrappingAlgorithm(kCCWRAPAES), CCrfc3394_iv, CCrfc3394_ivLen,
                                         k.baseAddress?.assumingMemoryBound(to: UInt8.self), kek.count,
                                         w.baseAddress?.assumingMemoryBound(to: UInt8.self), wrapped.count,
                                         o.baseAddress?.assumingMemoryBound(to: UInt8.self), &outLength)
                }
            }
        }
        return status == kCCSuccess ? out.prefix(outLength) : nil
    }

    /// AES-256-CBC with a zero IV, as backups use. Strips PKCS#7 padding
    /// when present; callers trim to the recorded size anyway.
    static func aesCBCDecrypt(_ data: Data, key: Data) throws -> Data {
        let capacity = data.count + kCCBlockSizeAES128
        var out = Data(count: capacity)
        var moved = 0
        let status = out.withUnsafeMutableBytes { o in
            data.withUnsafeBytes { d in
                key.withUnsafeBytes { k in
                    CCCrypt(CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmAES), 0,
                            k.baseAddress, key.count, nil,
                            d.baseAddress, data.count, o.baseAddress, capacity, &moved)
                }
            }
        }
        guard status == kCCSuccess else { throw BackupError.unreadable("decryption failed") }
        out.count = moved
        if let pad = out.last, pad > 0, pad <= 16, out.count >= Int(pad),
           out.suffix(Int(pad)).allSatisfy({ $0 == pad }) {
            out.removeLast(Int(pad))
        }
        return out
    }
}

// MARK: - SQLite

/// Just enough SQLite to read backup databases, read-only.
final class SQLiteDB {
    private var db: OpaquePointer?

    init(_ url: URL) throws {
        guard sqlite3_open_v2(url.path, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK else {
            throw BackupError.unreadable("can't open \(url.lastPathComponent)")
        }
    }

    deinit { sqlite3_close(db) }

    /// Every column as text (blobs as base64), nil for NULL.
    func rows(_ sql: String, _ params: [String] = []) throws -> [[String?]] {
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
            throw BackupError.unreadable(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(statement) }
        let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
        for (i, p) in params.enumerated() { sqlite3_bind_text(statement, Int32(i + 1), p, -1, transient) }
        var out: [[String?]] = []
        while sqlite3_step(statement) == SQLITE_ROW {
            out.append((0..<sqlite3_column_count(statement)).map { c in
                switch sqlite3_column_type(statement, c) {
                case SQLITE_NULL: return nil
                case SQLITE_BLOB:
                    let n = Int(sqlite3_column_bytes(statement, c))
                    guard let p = sqlite3_column_blob(statement, c) else { return nil }
                    return Data(bytes: p, count: n).base64EncodedString()
                default:
                    return sqlite3_column_text(statement, c).map { String(cString: $0) }
                }
            })
        }
        return out
    }
}
