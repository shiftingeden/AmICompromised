import Foundation

/// The distinct values a log scan saw: domains, process names, file paths,
/// IDs and addresses. Kept on the device after a scan so that later, when
/// researchers publish new indicators, the same traces can be re-checked
/// without a new sysdiagnose. Spyware campaigns are often published weeks
/// after the attacks they describe.
public struct TraceSet: Codable, Sendable {
    public var source: String
    public var capturedAt: Date
    public var domains: Set<String> = []
    public var processes: Set<String> = []
    public var paths: Set<String> = []
    public var profileIDs: Set<String> = []
    public var appIDs: Set<String> = []
    public var emails: Set<String> = []
    public var urls: Set<String> = []

    /// Per-kind cap so a huge archive can't produce an unbounded file.
    static let cap = 100_000

    public init(source: String, capturedAt: Date = Date()) {
        self.source = source
        self.capturedAt = capturedAt
    }

    public var count: Int {
        domains.count + processes.count + paths.count + profileIDs.count + appIDs.count + emails.count + urls.count
    }

    /// Matches every recorded trace against `indicators`. Only exact list
    /// matches are reported; the "unusual" heuristics need the original logs.
    public func recheck(against indicators: IndicatorSet) -> [Finding] {
        let scanner = LogScanner(indicators: indicators)
        var out = Findings(file: "Saved traces from \(source)")
        let detail = "Seen in your sysdiagnose from \(capturedAt.formatted(date: .abbreviated, time: .omitted)) and newly matched by an updated indicator list."
        for host in domains.sorted() { if let c = scanner.campaign(forDomain: host) { out.add(.match, "Domain", host, c, detail) } }
        for p in processes.sorted() { if let c = scanner.campaign(forProcess: p) { out.add(.match, "Process", p, c, detail) } }
        for p in paths.sorted() { if let c = scanner.campaign(forPath: p) { out.add(.match, "File path", p, c, detail) } }
        for id in profileIDs.sorted() { if let c = scanner.campaign(forProfile: id) { out.add(.match, "Configuration profile", id, c, detail) } }
        for id in appIDs.sorted() { if let c = scanner.campaign(forApp: id) { out.add(.match, "App ID", id, c, detail) } }
        for e in emails.sorted() { if let c = indicators.campaign(.email, e) { out.add(.match, "Email address", e, c, detail) } }
        for u in urls.sorted() { if let c = indicators.campaign(.url, u) { out.add(.match, "Web address", u, c, detail) } }
        return out.items
    }
}

/// Collects traces while a scan runs. A class so the scanner, a value type,
/// can share one across files.
public final class TraceRecorder: @unchecked Sendable {
    public private(set) var traces: TraceSet

    public init(source: String) { traces = TraceSet(source: source) }

    func domain(_ v: String) { insert(v, into: \.domains) }
    func process(_ v: String) { insert(v, into: \.processes) }
    func path(_ v: String) { insert(v, into: \.paths) }
    func profileID(_ v: String) { insert(v.uppercased(), into: \.profileIDs) }
    func appID(_ v: String) { insert(v, into: \.appIDs) }
    func email(_ v: String) { insert(v, into: \.emails) }
    func url(_ v: String) { insert(v, into: \.urls) }

    private func insert(_ value: String, into key: WritableKeyPath<TraceSet, Set<String>>) {
        guard traces[keyPath: key].count < TraceSet.cap else { return }
        traces[keyPath: key].insert(value)
    }
}
