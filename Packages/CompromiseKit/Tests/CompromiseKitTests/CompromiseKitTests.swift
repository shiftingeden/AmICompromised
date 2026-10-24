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
