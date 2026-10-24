import Foundation

/// A dotted version such as "18.6.2". Missing parts compare as zero, so
/// "18.6" == "18.6.0".
public struct OSVersion: Comparable, Hashable, Codable, CustomStringConvertible, Sendable {
    public let parts: [Int]

    public init(_ parts: [Int]) {
        var trimmed = parts
        while trimmed.count > 1, trimmed.last == 0 { trimmed.removeLast() }
        self.parts = trimmed
    }

    public init?(_ string: String) {
        let pieces = string.split(separator: ".").map { Int($0) }
        guard !pieces.isEmpty, !pieces.contains(nil) else { return nil }
        self.init(pieces.compactMap { $0 })
    }

    /// The OS this process is running on.
    public static var current: OSVersion {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        return OSVersion([v.majorVersion, v.minorVersion, v.patchVersion])
    }

    public var description: String {
        parts.count == 1 ? "\(parts[0]).0" : parts.map(String.init).joined(separator: ".")
    }

    public static func < (lhs: OSVersion, rhs: OSVersion) -> Bool {
        for i in 0..<max(lhs.parts.count, rhs.parts.count) {
            let l = i < lhs.parts.count ? lhs.parts[i] : 0
            let r = i < rhs.parts.count ? rhs.parts[i] : 0
            if l != r { return l < r }
        }
        return false
    }
}
