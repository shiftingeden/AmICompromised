import Foundation

/// One STIX2 file listed in mvt-indicators' `indicators.yaml`.
public struct IndicatorSource: Codable, Hashable, Identifiable, Sendable {
    public var name: String
    public var owner: String
    public var repo: String
    public var branch: String
    public var path: String

    public var id: String { "\(owner)/\(repo)/\(path)" }

    public var rawURL: URL {
        URL(string: "https://raw.githubusercontent.com/\(owner)/\(repo)/\(branch)/\(path)")!
    }

    public static let indexURL = URL(string: "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/indicators.yaml")!

    /// Optional extra lists (off by default): published indicators that
    /// mvt-indicators doesn't list, reformatted into STIX by this project's
    /// data repo. Same layout as `indicators.yaml`.
    public static let extraIndexURL = URL(string: "https://raw.githubusercontent.com/shiftingeden/AmICompromised-data/main/extra-indicators.yaml")!

    /// Reads the few keys we need from `indicators.yaml`. The file is a flat
    /// list of `-` items, so a line scanner is enough and avoids a YAML
    /// dependency.
    public static func parseIndex(_ text: String) -> [IndicatorSource] {
        var sources: [IndicatorSource] = []
        var fields: [String: String] = [:]

        func flush() {
            if let name = fields["name"], let owner = fields["owner"], let repo = fields["repo"],
               let path = fields["path"] {
                sources.append(IndicatorSource(name: name, owner: owner, repo: repo,
                                               branch: fields["branch"] ?? "main", path: path))
            }
            fields = [:]
        }

        for raw in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line == "-" { flush(); continue }
            guard let colon = line.firstIndex(of: ":") else { continue }
            let key = String(line[..<colon])
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            // The first `name:` in an item is the campaign; later ones belong
            // to nested blocks.
            if !value.isEmpty, fields[key] == nil { fields[key] = value }
        }
        flush()
        return sources
    }

    public static var bundledIndex: [IndicatorSource] {
        let url = Bundle.module.url(forResource: "indicators", withExtension: "yaml")!
        return parseIndex((try? String(contentsOf: url, encoding: .utf8)) ?? "")
    }

    public static var bundledExtraIndex: [IndicatorSource] {
        let url = Bundle.module.url(forResource: "extra-indicators", withExtension: "yaml")!
        return parseIndex((try? String(contentsOf: url, encoding: .utf8)) ?? "")
    }
}

/// Every indicator we know, keyed by value, with the campaign it came from.
public struct IndicatorSet: Codable, Sendable {
    public enum Kind: String, Codable, CaseIterable, Sendable {
        case domain, process, filePath, fileName, profileID, appID, email, url
    }

    public var values: [Kind: [String: String]] = [:]
    public var sourceCounts: [String: Int] = [:]
    public var updated: Date?
    /// Campaigns that came from the optional extra lists. Optional so sets
    /// saved by earlier versions still decode.
    public var extraCampaigns: Set<String>?

    public func isExtra(_ campaign: String) -> Bool { extraCampaigns?.contains(campaign) ?? false }

    public init() {}

    public var total: Int { values.values.reduce(0) { $0 + $1.count } }

    public func campaign(_ kind: Kind, _ value: String) -> String? {
        values[kind]?[value]
    }

    public func all(_ kind: Kind) -> [String: String] { values[kind] ?? [:] }

    mutating func insert(_ kind: Kind, _ value: String, campaign: String) {
        guard !value.isEmpty else { return }
        values[kind, default: [:]][value] = campaign
    }

    /// Adds the indicators in one STIX2 bundle. Returns how many were added.
    @discardableResult
    public mutating func addSTIX(_ data: Data, campaign: String) throws -> Int {
        guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let objects = root["objects"] as? [[String: Any]] else { return 0 }
        var added = 0
        for object in objects where object["type"] as? String == "indicator" {
            guard let pattern = object["pattern"] as? String else { continue }
            for (kind, value) in Self.parsePattern(pattern) {
                insert(kind, value, campaign: campaign)
                added += 1
            }
        }
        sourceCounts[campaign] = added
        return added
    }

    /// Pulls `type:property='value'` comparisons out of a STIX pattern such
    /// as `[domain-name:value='example.com']`.
    static func parsePattern(_ pattern: String) -> [(Kind, String)] {
        let regex = #/([a-z0-9-]+):([a-z_.]+)\s*=\s*'((?:[^'\\]|\\.)*)'/#
        return pattern.matches(of: regex).compactMap { m in
            let value = String(m.3).replacingOccurrences(of: "\\'", with: "'")
            switch (m.1, m.2) {
            case ("domain-name", "value"): return (.domain, value.lowercased())
            case ("process", "name"): return (.process, value)
            case ("file", "path"): return (.filePath, value)
            case ("file", "name"): return (.fileName, value)
            case ("configuration-profile", "id"): return (.profileID, value.uppercased())
            case ("app", "id"): return (.appID, value)
            case ("email-addr", "value"): return (.email, value.lowercased())
            case ("url", "value"): return (.url, value)
            default: return nil
            }
        }
    }
}
