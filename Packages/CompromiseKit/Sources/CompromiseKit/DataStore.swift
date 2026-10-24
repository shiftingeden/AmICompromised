import Foundation

/// Downloads the indicator lists and the exploited-bug catalog, and keeps the
/// last good copy on disk so scans work offline.
public actor DataStore {
    /// The generated catalog, published from this project's data repo.
    /// Until that repo exists the fetch fails and the bundled copy is used.
    public static let catalogURL = URL(string: "https://raw.githubusercontent.com/shiftingeden/AmICompromised-data/main/apple-kev.json")!

    private let directory: URL
    private let session: URLSession

    public init(directory: URL? = nil, session: URLSession = .shared) {
        let base = directory ?? FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("CompromiseKit", isDirectory: true)
        try? FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        self.directory = base
        self.session = session
    }

    private var indicatorsFile: URL { directory.appendingPathComponent("indicators.json") }
    private var catalogFile: URL { directory.appendingPathComponent("apple-kev.json") }

    // MARK: Indicators

    public func cachedIndicators() -> IndicatorSet? {
        guard let data = try? Data(contentsOf: indicatorsFile) else { return nil }
        return try? JSONDecoder().decode(IndicatorSet.self, from: data)
    }

    public struct IndicatorUpdate: Sendable {
        public var set: IndicatorSet
        public var failedSources: [String]
    }

    /// Fetches the index and every STIX file it lists. A source that fails
    /// keeps its indicators from the previous download.
    public func updateIndicators() async throws -> IndicatorUpdate {
        let sources: [IndicatorSource]
        if let (data, _) = try? await fetch(IndicatorSource.indexURL),
           case let parsed = IndicatorSource.parseIndex(String(decoding: data, as: UTF8.self)),
           !parsed.isEmpty {
            sources = parsed
        } else {
            sources = IndicatorSource.bundledIndex
        }

        let previous = cachedIndicators()
        var set = IndicatorSet()
        var failed: [String] = []

        await withTaskGroup(of: (IndicatorSource, Data?).self) { group in
            for source in sources {
                group.addTask { (source, try? await self.fetch(source.rawURL).0) }
            }
            for await (source, data) in group {
                if let data, (try? set.addSTIX(data, campaign: source.name)) ?? 0 > 0 { continue }
                failed.append(source.name)
                if let previous { set.carryOver(source.name, from: previous) }
            }
        }

        if set.total == 0 { throw URLError(.cannotLoadFromNetwork) }
        set.updated = Date()
        try JSONEncoder().encode(set).write(to: indicatorsFile, options: .atomic)
        return IndicatorUpdate(set: set, failedSources: failed.sorted())
    }

    // MARK: Exploited bugs

    public func catalog() -> ExploitedBugCatalog {
        if let data = try? Data(contentsOf: catalogFile),
           let cached = try? ExploitedBugCatalog.decode(data) {
            let bundled = ExploitedBugCatalog.bundled
            return cached.generated >= bundled.generated ? cached : bundled
        }
        return .bundled
    }

    public func updateCatalog() async -> ExploitedBugCatalog {
        if let (data, _) = try? await fetch(Self.catalogURL),
           let fresh = try? ExploitedBugCatalog.decode(data), !fresh.entries.isEmpty {
            try? data.write(to: catalogFile, options: .atomic)
        }
        return catalog()
    }

    private func fetch(_ url: URL) async throws -> (Data, URLResponse) {
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 30)
        request.setValue("AmICompromised", forHTTPHeaderField: "User-Agent")
        let (data, response) = try await session.data(for: request)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw URLError(.badServerResponse) }
        return (data, response)
    }
}

extension IndicatorSet {
    mutating func carryOver(_ campaign: String, from other: IndicatorSet) {
        var count = 0
        for (kind, map) in other.values {
            for (value, c) in map where c == campaign {
                insert(kind, value, campaign: c)
                count += 1
            }
        }
        if count > 0 { sourceCounts[campaign] = count }
    }
}
