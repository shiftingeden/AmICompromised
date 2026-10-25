import Foundation

public struct LogScanReport: Codable, Sendable {
    public var archiveName: String
    public var scannedAt: Date
    public var findings: [Finding]
    public var filesScanned: Int
    public var bytesScanned: Int
    public var indicatorCount: Int
    public var sawShutdownLog: Bool
    public var sawProcessList: Bool
    public var crashLogCount: Int

    public var matches: [Finding] { findings.filter { $0.level == .match } }
    public var suspicious: [Finding] { findings.filter { $0.level == .suspicious } }

    /// The archive didn't have the files that matter most, so the result
    /// says less than usual.
    public var looksIncomplete: Bool { !sawShutdownLog && !sawProcessList }
}

/// Scans a sysdiagnose, either the .tar.gz the phone produces or an
/// extracted folder (on the Mac).
public enum SysdiagnoseScanner {
    static let maxFileSize = 64 << 20
    static let skippedExtensions: Set<String> = [
        "tracev3", "png", "jpg", "jpeg", "heic", "gz", "tgz", "tar", "zip", "db", "sqlite",
        "sqlite-wal", "sqlite-shm", "plsql", "epsql", "dat", "bin", "timesync", "pcap", "pcapng",
    ]

    public static func scan(_ url: URL, indicators: IndicatorSet, recorder: TraceRecorder? = nil,
                            progress: @Sendable (Double) -> Void = { _ in }) throws -> LogScanReport {
        var report = LogScanReport(archiveName: url.lastPathComponent, scannedAt: Date(), findings: [],
                                   filesScanned: 0, bytesScanned: 0, indicatorCount: indicators.total,
                                   sawShutdownLog: false, sawProcessList: false, crashLogCount: 0)
        var scanner = LogScanner(indicators: indicators)
        scanner.recorder = recorder

        func handle(path: String, data: Data) {
            let name = (path as NSString).lastPathComponent
            if name == "shutdown.log" { report.sawShutdownLog = true }
            if name == "ps.txt" { report.sawProcessList = true }
            if name.hasSuffix(".ips") { report.crashLogCount += 1 }
            report.filesScanned += 1
            report.bytesScanned += data.count
            report.findings += scanner.scan(path: path, data: data)
        }

        var isDirectory: ObjCBool = false
        FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory)
        if isDirectory.boolValue {
            try scanFolder(url, progress: progress, handle: handle)
        } else {
            try scanArchive(url, progress: progress, handle: handle)
        }
        progress(1)
        return report
    }

    static func shouldRead(path: String, size: Int) -> Bool {
        guard size > 0, size <= maxFileSize else { return false }
        let name = (path as NSString).lastPathComponent
        if name.hasPrefix("._") { return false }
        return !skippedExtensions.contains((name as NSString).pathExtension.lowercased())
    }

    /// Binary files (bplists, databases without an extension) have NUL bytes
    /// early on; text logs don't.
    static func isText(_ data: Data) -> Bool {
        !data.prefix(4096).contains(0)
    }

    private static func scanArchive(_ url: URL, progress: (Double) -> Void,
                                    handle: (String, Data) -> Void) throws {
        let total = Double((try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 1)
        let tar = TarReader(gzip: try GzipReader(url: url))
        var lastReported = 0.0
        while let entry = try tar.next() {
            if entry.isFile, shouldRead(path: entry.path, size: entry.size) {
                let data = try tar.readData(entry)
                if isText(data) { handle(entry.path, data) }
            } else if entry.isFile, entry.path.hasSuffix(".ips") {
                handle(entry.path, Data())   // the name alone is worth checking
            }
            let fraction = min(0.99, Double(tar.compressedBytesRead) / total)
            if fraction - lastReported >= 0.01 { progress(fraction); lastReported = fraction }
        }
    }

    private static func scanFolder(_ url: URL, progress: (Double) -> Void,
                                   handle: (String, Data) -> Void) throws {
        let keys: [URLResourceKey] = [.isRegularFileKey, .fileSizeKey]
        guard let walker = FileManager.default.enumerator(at: url, includingPropertiesForKeys: keys) else { return }
        let files = walker.compactMap { $0 as? URL }
        for (i, file) in files.enumerated() {
            let values = try? file.resourceValues(forKeys: Set(keys))
            guard values?.isRegularFile == true else { continue }
            let relative = String(file.path.dropFirst(url.path.count + 1))
            if shouldRead(path: relative, size: values?.fileSize ?? 0),
               let data = try? Data(contentsOf: file, options: .mappedIfSafe), isText(data) {
                handle(relative, data)
            } else if relative.hasSuffix(".ips") {
                handle(relative, Data())
            }
            progress(Double(i + 1) / Double(max(files.count, 1)))
        }
    }
}
