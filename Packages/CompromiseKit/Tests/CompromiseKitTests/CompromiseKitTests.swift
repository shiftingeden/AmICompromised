import XCTest
@testable import CompromiseKit

final class CompromiseKitTests: XCTestCase {
    func testVersionOrdering() {
        XCTAssertEqual(OSVersion("18.6"), OSVersion("18.6.0"))
        XCTAssertLessThan(OSVersion("18.6.1")!, OSVersion("18.6.2")!)
        XCTAssertLessThan(OSVersion("9.9")!, OSVersion("18.0")!)
        XCTAssertNil(OSVersion("18.beta"))
    }

    func testCatalogAssessment() throws {
        let json = """
        {"generated":"2026-10-23","entries":[
          {"cve":"CVE-1","name":"a","summary":"","dateAdded":"","ranges":[{"versionStartIncluding":"17.0","versionEndExcluding":"18.6.2"}]},
          {"cve":"CVE-2","name":"b","summary":"","dateAdded":"","ranges":[{"versionEndExcluding":"18.7"}]},
          {"cve":"CVE-3","name":"c","summary":"","dateAdded":"","ranges":[{"versionEndExcluding":"16.0"}]}
        ]}
        """
        let catalog = try ExploitedBugCatalog.decode(Data(json.utf8))
        let a = catalog.assess(OSVersion("18.5")!)
        XCTAssertEqual(a.affecting.map(\.cve), ["CVE-1", "CVE-2"])
        XCTAssertEqual(a.updateTo, OSVersion("18.7"))
        XCTAssertTrue(catalog.assess(OSVersion("26.0")!).affecting.isEmpty)
    }

    func testBundledDataLoads() {
        XCTAssertGreaterThan(ExploitedBugCatalog.bundled.entries.count, 50)
        let index = IndicatorSource.bundledIndex
        XCTAssertGreaterThan(index.count, 10)
        XCTAssertTrue(index.contains { $0.name.contains("Pegasus") && $0.owner == "AmnestyTech" })
    }

    func testPatternParsing() {
        let p = IndicatorSet.parsePattern("[domain-name:value='Evil.Example.com']")
        XCTAssertEqual(p.first?.0, .domain)
        XCTAssertEqual(p.first?.1, "evil.example.com")
        XCTAssertEqual(IndicatorSet.parsePattern("[process:name='bh']").first?.1, "bh")
    }

    func sampleIndicators() throws -> IndicatorSet {
        let stix = """
        {"type":"bundle","objects":[
          {"type":"indicator","pattern":"[domain-name:value='badhost.xyz']"},
          {"type":"indicator","pattern":"[process:name='bh']"},
          {"type":"indicator","pattern":"[process:name='roleaboutd']"},
          {"type":"indicator","pattern":"[file:path='/private/var/tmp/hooker']"},
          {"type":"indicator","pattern":"[app:id='com.stalker.app']"},
          {"type":"indicator","pattern":"[domain-name:value='update.app']"}
        ]}
        """
        var set = IndicatorSet()
        XCTAssertEqual(try set.addSTIX(Data(stix.utf8), campaign: "Test"), 6)
        return set
    }

    func testTokenMatching() throws {
        let scanner = LogScanner(indicators: try sampleIndicators())
        let log = """
        connect to https://cdn.badhost.xyz/x?y=1 ok
        bh is a word that must not match here
        loaded com.update.app and com.stalker.app
        wrote /private/var/tmp/hooker.
        """
        let found = scanner.scan(path: "logs/a.log", data: Data(log.utf8))
        XCTAssertEqual(Set(found.map(\.kind)), ["Domain", "App ID", "File path"])
        XCTAssertEqual(found.first { $0.kind == "Domain" }?.value, "cdn.badhost.xyz")
    }

    func testProcessListsAndShutdownLog() throws {
        let scanner = LogScanner(indicators: try sampleIndicators())
        let ps = """
        USER  PID COMMAND
        root  12  /usr/libexec/roleaboutd -x
        root  13  /usr/sbin/notifyd
        """
        XCTAssertEqual(scanner.scan(path: "ps.txt", data: Data(ps.utf8)).map(\.kind), ["Running process"])

        let shutdown = """
        remaining client pid: 99 (/private/var/db/com.apple.xpc.roleaccountd.staging/bh)
        remaining client pid: 100 (/private/var/db/oddthing)
        remaining client pid: 101 (/usr/libexec/backboardd)
        """
        let found = scanner.scan(path: "system_logs.logarchive/Extra/shutdown.log", data: Data(shutdown.utf8))
        XCTAssertEqual(found.filter { $0.level == .match }.count, 1)
        XCTAssertEqual(found.filter { $0.level == .suspicious }.map(\.value), ["/private/var/db/oddthing"])
        XCTAssertEqual(LogScanner.crashLogProcess("bh-2026-01-02-030405.ips"), "bh")
    }

    func testArchiveScan() throws {
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let root = tmp.appendingPathComponent("sysdiagnose_2026.10.23_test")
        let deep = root.appendingPathComponent("system_logs.logarchive/Extra/" + String(repeating: "long/", count: 25))
        try FileManager.default.createDirectory(at: deep, withIntermediateDirectories: true)
        try "remaining client pid: 1 (/private/var/tmp/bh)\n".write(
            to: root.appendingPathComponent("system_logs.logarchive/Extra/shutdown.log"), atomically: true, encoding: .utf8)
        try "USER PID COMMAND\nroot 1 /sbin/launchd\n".write(to: root.appendingPathComponent("ps.txt"), atomically: true, encoding: .utf8)
        try "dns query badhost.xyz\n".write(to: deep.appendingPathComponent("net.log"), atomically: true, encoding: .utf8)
        try Data((0..<300_000).map { UInt8($0 % 251) }).write(to: root.appendingPathComponent("blob.bin"))
        try Data().write(to: root.appendingPathComponent("roleaboutd-2026-01-02-030405.ips"))

        let archive = tmp.appendingPathComponent("sysdiagnose.tar.gz")
        let tar = Process()
        tar.executableURL = URL(fileURLWithPath: "/usr/bin/tar")
        tar.arguments = ["-czf", archive.path, "-C", tmp.path, root.lastPathComponent]
        try tar.run(); tar.waitUntilExit()

        for target in [archive, root] {
            let report = try SysdiagnoseScanner.scan(target, indicators: try sampleIndicators())
            XCTAssertTrue(report.sawShutdownLog)
            XCTAssertTrue(report.sawProcessList)
            XCTAssertEqual(Set(report.matches.map(\.kind)), ["Process at shutdown", "Domain", "Crashed process"], "\(target)")
        }
        try? FileManager.default.removeItem(at: tmp)
    }

    func testRejectsNonGzip() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("not.tar.gz")
        try Data("hello world".utf8).write(to: url)
        XCTAssertThrowsError(try SysdiagnoseScanner.scan(url, indicators: IndicatorSet()))
    }
}

/// Hits GitHub. Run with LIVE=1 swift test --filter LiveTests
final class LiveTests: XCTestCase {
    func testDownloadIndicators() async throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["LIVE"] == "1")
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let update = try await DataStore(directory: dir).updateIndicators()
        for kind in IndicatorSet.Kind.allCases { print("LIVE", kind, update.set.all(kind).count) }
        print("LIVE failed:", update.failedSources)
        print("LIVE sources:", update.set.sourceCounts.sorted { $0.key < $1.key })
        XCTAssertGreaterThan(update.set.all(.domain).count, 1000)
    }
}

#if os(macOS)
/// Scans this Mac for real. Run with LIVE=1 swift test --filter LiveMacScan
final class LiveMacScan: XCTestCase {
    func testScanThisMac() async throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["LIVE"] == "1")
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let set = try await DataStore(directory: dir).updateIndicators().set
        let start = Date()
        let report = MacSystemScanner(indicators: set, fullAccess: true).scan()
        print("MAC took \(Int(Date().timeIntervalSince(start)))s")
        for c in report.checks { print("MAC [\(c.status)] \(c.title): \(c.detail) (\(c.items.count) items)") }
        for f in report.findings { print("MAC FINDING [\(f.level)] \(f.kind): \(f.value)") }
        let a = ExploitedBugCatalog.bundled.assess(.current, on: .macOS)
        print("MAC macOS \(a.version): \(a.affecting.count) exploited bugs, update to \(a.updateTo?.description ?? "-")")
    }
}
#endif

// MARK: - Backups

import CommonCrypto

/// Stands in for Apple's MBFile so the archive has EncryptionKey and Size
/// keys the way real Manifest.db rows do.
@objc(MBFile) final class FakeMBFile: NSObject, NSSecureCoding {
    static var supportsSecureCoding: Bool { true }
    let key: Data, size: Int
    init(key: Data, size: Int) { self.key = key; self.size = size }
    func encode(with coder: NSCoder) {
        coder.encode(NSMutableData(data: key), forKey: "EncryptionKey")
        coder.encode(size, forKey: "Size")
        coder.encode(3, forKey: "ProtectionClass")
    }
    init?(coder: NSCoder) { nil }
}

final class BackupTests: XCTestCase {
    func wrap(_ key: Data, kek: Data) -> Data {
        var len = CCSymmetricWrappedSize(CCWrappingAlgorithm(kCCWRAPAES), key.count)
        var out = Data(count: len)
        _ = out.withUnsafeMutableBytes { o in key.withUnsafeBytes { k in kek.withUnsafeBytes { e in
            CCSymmetricKeyWrap(CCWrappingAlgorithm(kCCWRAPAES), CCrfc3394_iv, CCrfc3394_ivLen,
                               e.baseAddress!.assumingMemoryBound(to: UInt8.self), kek.count,
                               k.baseAddress!.assumingMemoryBound(to: UInt8.self), key.count,
                               o.baseAddress!.assumingMemoryBound(to: UInt8.self), &len) } } }
        return out.prefix(len)
    }

    func encrypt(_ data: Data, key: Data) -> Data {
        var out = Data(count: data.count + 32); var moved = 0
        let n = out.count
        _ = out.withUnsafeMutableBytes { o in data.withUnsafeBytes { d in key.withUnsafeBytes { k in
            CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding),
                    k.baseAddress, key.count, nil, d.baseAddress, data.count, o.baseAddress, n, &moved) } } }
        return out.prefix(moved)
    }

    func random(_ n: Int) -> Data { Data((0..<n).map { _ in UInt8.random(in: 0...255) }) }

    func tlv(_ tag: String, _ value: Data) -> Data {
        var d = Data(tag.utf8); let n = UInt32(value.count).bigEndian
        withUnsafeBytes(of: n) { d.append(contentsOf: $0) }; return d + value
    }
    func be(_ v: UInt32) -> Data { withUnsafeBytes(of: v.bigEndian) { Data($0) } }

    func sqlite(_ url: URL, _ sql: String) throws {
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/sqlite3")
        p.arguments = [url.path, sql]; try p.run(); p.waitUntilExit()
    }

    func makeBackup(encrypted: Bool, password: String = "hunter2") throws -> URL {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("bk-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        let history = root.appendingPathComponent("plain-history.db")
        try sqlite(history, "CREATE TABLE history_items(url TEXT); INSERT INTO history_items VALUES('https://news.example.org/a'),('https://x.badhost.xyz/track');")
        let historyData = try Data(contentsOf: history)
        let fileID = "3d0d7e5fb2ce288813306e4d4636395e047a3d28"

        // Keys: one class key (class 3) wrapped by the password key.
        let salt = random(20), dpsl = random(20)
        let pass1 = try Crypto.pbkdf2(Data(password.utf8), salt: dpsl, rounds: 1000, prf: CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256))
        let passKey = try Crypto.pbkdf2(pass1, salt: salt, rounds: 10, prf: CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1))
        let classKey = random(32), fileKey = random(32), manifestKey = random(32)
        func classBlob(_ key: Data) -> Data { Data([3, 0, 0, 0]) + wrap(key, kek: classKey) }

        let meta = try NSKeyedArchiver.archivedData(withRootObject: FakeMBFile(key: classBlob(fileKey), size: historyData.count),
                                                    requiringSecureCoding: false)
        let manifestPlain = root.appendingPathComponent("manifest-plain.db")
        try sqlite(manifestPlain, """
            CREATE TABLE Files(fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB);
            INSERT INTO Files VALUES('\(fileID)','HomeDomain','Library/Safari/History.db',1,X'\(meta.map { String(format: "%02X", $0) }.joined())');
            INSERT INTO Files VALUES('aa','AppDomain-com.stalker.app','Library',2,NULL);
            """)
        try FileManager.default.createDirectory(at: root.appendingPathComponent("3d"), withIntermediateDirectories: true)

        var manifest: [String: Any] = ["IsEncrypted": encrypted, "Lockdown": ["ProductVersion": "18.5", "DeviceName": "Test iPhone"]]
        if encrypted {
            try encrypt(historyData, key: fileKey).write(to: root.appendingPathComponent("3d/\(fileID)"))
            try encrypt(Data(contentsOf: manifestPlain), key: manifestKey).write(to: root.appendingPathComponent("Manifest.db"))
            manifest["ManifestKey"] = classBlob(manifestKey)
            let parts: [Data] = [
                tlv("VERS", be(3)), tlv("UUID", random(16)), tlv("WRAP", be(1)),
                tlv("SALT", salt), tlv("ITER", be(10)), tlv("DPWT", be(1)), tlv("DPIC", be(1000)), tlv("DPSL", dpsl),
                tlv("UUID", random(16)), tlv("CLAS", be(3)), tlv("WRAP", be(3)), tlv("KTYP", be(0)),
                tlv("WPKY", wrap(classKey, kek: passKey)),
            ]
            manifest["BackupKeyBag"] = parts.reduce(Data(), +)
        } else {
            try historyData.write(to: root.appendingPathComponent("3d/\(fileID)"))
            try FileManager.default.copyItem(at: manifestPlain, to: root.appendingPathComponent("Manifest.db"))
        }
        (manifest as NSDictionary).write(to: root.appendingPathComponent("Manifest.plist"), atomically: true)
        (["Device Name": "Test iPhone", "Product Version": "18.5"] as NSDictionary)
            .write(to: root.appendingPathComponent("Info.plist"), atomically: true)
        try? FileManager.default.removeItem(at: history)
        try? FileManager.default.removeItem(at: manifestPlain)
        return root
    }

    func indicators() throws -> IndicatorSet {
        var set = IndicatorSet()
        try set.addSTIX(Data("""
        {"objects":[{"type":"indicator","pattern":"[domain-name:value='badhost.xyz']"},
                    {"type":"indicator","pattern":"[app:id='com.stalker.app']"}]}
        """.utf8), campaign: "Test")
        return set
    }

    func testEncryptedBackup() throws {
        let folder = try makeBackup(encrypted: true)
        let info = try BackupInfo(folder: folder)
        XCTAssertTrue(info.isEncrypted)
        XCTAssertThrowsError(try BackupScanner(info: info, indicators: indicators(), password: nil))
        XCTAssertThrowsError(try BackupScanner(info: info, indicators: indicators(), password: "wrong"))
        let report = try BackupScanner(info: info, indicators: indicators(), password: "hunter2").scan()
        XCTAssertEqual(Set(report.matches.map(\.kind)), ["Domain", "Installed app"], "\(report.findings)")
        XCTAssertTrue(report.coverage.contains { $0.hasPrefix("Safari history: 2") }, "\(report.coverage)")
    }

    func testUnencryptedBackup() throws {
        let folder = try makeBackup(encrypted: false)
        let report = try BackupScanner(info: BackupInfo(folder: folder), indicators: indicators(), password: nil).scan()
        XCTAssertEqual(Set(report.matches.map(\.kind)), ["Domain", "Installed app"])
    }
}

final class TraceTests: XCTestCase {
    func testRecheckFindsTracesPublishedLater() throws {
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("tr-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        try "USER PID COMMAND\nroot 1 /usr/libexec/latespyd\n".write(to: tmp.appendingPathComponent("ps.txt"), atomically: true, encoding: .utf8)
        try "fetched https://cdn.laterhost.net/a.js and /private/var/tmp/dropper\n".write(
            to: tmp.appendingPathComponent("net.log"), atomically: true, encoding: .utf8)

        // Scan today: nothing on the lists yet.
        let recorder = TraceRecorder(source: "test")
        let report = try SysdiagnoseScanner.scan(tmp, indicators: IndicatorSet(), recorder: recorder)
        XCTAssertTrue(report.findings.isEmpty)
        XCTAssertTrue(recorder.traces.domains.contains("cdn.laterhost.net"))
        XCTAssertTrue(recorder.traces.processes.contains("latespyd"))

        // Weeks later a campaign is published.
        var later = IndicatorSet()
        try later.addSTIX(Data("""
        {"objects":[{"type":"indicator","pattern":"[domain-name:value='laterhost.net']"},
                    {"type":"indicator","pattern":"[process:name='latespyd']"},
                    {"type":"indicator","pattern":"[file:path='/private/var/tmp/dropper']"}]}
        """.utf8), campaign: "Late")
        let data = try JSONEncoder().encode(recorder.traces)
        let saved = try JSONDecoder().decode(TraceSet.self, from: data)
        XCTAssertEqual(Set(saved.recheck(against: later).map(\.kind)), ["Domain", "Process", "File path"])
    }
}
