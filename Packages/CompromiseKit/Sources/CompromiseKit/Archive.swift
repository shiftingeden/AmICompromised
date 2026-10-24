import Compression
import Foundation

public enum ArchiveError: LocalizedError {
    case notGzip, corrupt, unsupported

    public var errorDescription: String? {
        switch self {
        case .notGzip: "This file isn't a sysdiagnose archive (.tar.gz)."
        case .corrupt: "The archive is damaged or incomplete. Try generating a new sysdiagnose."
        case .unsupported: "This archive uses a format the scanner doesn't support."
        }
    }
}

/// Streams the decompressed bytes of a .gz file without loading it into
/// memory. Sysdiagnose archives run to hundreds of megabytes.
final class GzipReader {
    private let handle: FileHandle
    private let stream: UnsafeMutablePointer<compression_stream>
    private let src: UnsafeMutablePointer<UInt8>
    private let srcCapacity = 1 << 20
    private var eof = false
    private var finished = false
    private(set) var compressedBytesRead = 0

    init(url: URL) throws {
        handle = try FileHandle(forReadingFrom: url)
        stream = .allocate(capacity: 1)
        src = .allocate(capacity: srcCapacity)
        guard compression_stream_init(stream, COMPRESSION_STREAM_DECODE, COMPRESSION_ZLIB) == COMPRESSION_STATUS_OK else {
            throw ArchiveError.corrupt
        }
        let head = try handle.read(upToCount: 64 * 1024) ?? Data()
        compressedBytesRead = head.count
        let offset = try Self.headerLength(head)
        let body = head.dropFirst(offset)
        body.copyBytes(to: src, count: body.count)
        stream.pointee.src_ptr = UnsafePointer(src)
        stream.pointee.src_size = body.count
        eof = head.count < 64 * 1024
    }

    deinit {
        compression_stream_destroy(stream)
        stream.deallocate()
        src.deallocate()
        try? handle.close()
    }

    /// Size of the gzip member header (RFC 1952), so the raw deflate data
    /// can go to Compression's ZLIB decoder.
    static func headerLength(_ d: Data) throws -> Int {
        let b = [UInt8](d.prefix(10))
        guard b.count == 10, b[0] == 0x1f, b[1] == 0x8b, b[2] == 8 else { throw ArchiveError.notGzip }
        let flags = b[3]
        var i = 10
        let bytes = [UInt8](d)
        if flags & 4 != 0 {
            guard i + 2 <= bytes.count else { throw ArchiveError.corrupt }
            i += 2 + Int(bytes[i]) + Int(bytes[i + 1]) << 8
        }
        for flag: UInt8 in [8, 16] where flags & flag != 0 {
            while i < bytes.count, bytes[i] != 0 { i += 1 }
            i += 1
        }
        if flags & 2 != 0 { i += 2 }
        guard i <= bytes.count else { throw ArchiveError.corrupt }
        return i
    }

    /// Up to `count` decompressed bytes; empty at the end of the stream.
    func read(_ count: Int) throws -> Data {
        guard !finished else { return Data() }
        var out = Data(count: count)
        var produced = 0
        try out.withUnsafeMutableBytes { (dst: UnsafeMutableRawBufferPointer) in
            let base = dst.bindMemory(to: UInt8.self).baseAddress!
            while produced < count, !finished {
                if stream.pointee.src_size == 0, !eof {
                    let chunk = try handle.read(upToCount: srcCapacity) ?? Data()
                    compressedBytesRead += chunk.count
                    if chunk.count < srcCapacity { eof = true }
                    chunk.copyBytes(to: src, count: chunk.count)
                    stream.pointee.src_ptr = UnsafePointer(src)
                    stream.pointee.src_size = chunk.count
                }
                stream.pointee.dst_ptr = base + produced
                stream.pointee.dst_size = count - produced
                let flags = eof && stream.pointee.src_size == 0 ? Int32(COMPRESSION_STREAM_FINALIZE.rawValue) : 0
                let status = compression_stream_process(stream, flags)
                let newProduced = count - stream.pointee.dst_size
                switch status {
                case COMPRESSION_STATUS_END:
                    finished = true
                case COMPRESSION_STATUS_OK:
                    // No progress with no input left means a truncated file.
                    if newProduced == produced, eof, stream.pointee.src_size == 0 { throw ArchiveError.corrupt }
                default:
                    throw ArchiveError.corrupt
                }
                produced = newProduced
            }
        }
        out.count = produced
        return out
    }
}

public struct TarEntry: Sendable {
    public var path: String
    public var size: Int
    public var isFile: Bool
}

/// Reads ustar / GNU / pax tar entries from a byte stream.
final class TarReader {
    private let gzip: GzipReader
    private var buffer = Data()
    private var pending = 0   // unread bytes of the current entry, padding included

    init(gzip: GzipReader) { self.gzip = gzip }

    var compressedBytesRead: Int { gzip.compressedBytesRead }

    private func take(_ n: Int) throws -> Data {
        while buffer.count < n {
            let more = try gzip.read(max(256 * 1024, n - buffer.count))
            if more.isEmpty { throw ArchiveError.corrupt }
            buffer.append(more)
        }
        let out = buffer.prefix(n)
        buffer.removeFirst(n)
        return Data(out)
    }

    private func skip(_ n: Int) throws {
        var left = n
        while left > 0 {
            let step = min(left, 1 << 20)
            _ = try take(step)
            left -= step
        }
    }

    private static func padded(_ n: Int) -> Int { (n + 511) / 512 * 512 }

    func next() throws -> TarEntry? {
        if pending > 0 { try skip(pending); pending = 0 }
        var longName: String?
        while true {
            let header: Data
            do { header = try take(512) } catch { return nil }   // missing end blocks
            if header.allSatisfy({ $0 == 0 }) { return nil }
            let h = [UInt8](header)
            let size = try Self.number(h[124..<136])
            let type = h[156]
            switch type {
            case UInt8(ascii: "L"):
                let data = try take(Self.padded(size))
                longName = Self.string(data.prefix(size))
                continue
            case UInt8(ascii: "x"):
                let data = try take(Self.padded(size))
                longName = Self.paxPath(data.prefix(size)) ?? longName
                continue
            case UInt8(ascii: "g"):
                try skip(Self.padded(size))
                continue
            default:
                break
            }
            var path = Self.string(h[0..<100])
            if h[257..<262].elementsEqual("ustar".utf8) {
                let prefix = Self.string(h[345..<500])
                if !prefix.isEmpty { path = prefix + "/" + path }
            }
            if let longName { path = longName }
            let isFile = type == 0 || type == UInt8(ascii: "0") || type == UInt8(ascii: "7")
            pending = Self.padded(size)
            return TarEntry(path: path, size: size, isFile: isFile)
        }
    }

    /// The current entry's contents. Call at most once per entry.
    func readData(_ entry: TarEntry) throws -> Data {
        let data = try take(Self.padded(entry.size))
        pending = 0
        return data.prefix(entry.size)
    }

    private static func string<S: Sequence>(_ bytes: S) -> String where S.Element == UInt8 {
        String(decoding: bytes.prefix { $0 != 0 }, as: UTF8.self)
    }

    private static func number(_ field: ArraySlice<UInt8>) throws -> Int {
        if let first = field.first, first & 0x80 != 0 {   // GNU base-256
            return field.dropFirst().reduce(Int(first & 0x7f)) { $0 << 8 | Int($1) }
        }
        let text = string(field).trimmingCharacters(in: .whitespaces)
        if text.isEmpty { return 0 }
        guard let n = Int(text, radix: 8) else { throw ArchiveError.unsupported }
        return n
    }

    private static func paxPath(_ data: Data) -> String? {
        for record in String(decoding: data, as: UTF8.self).split(separator: "\n") {
            if let r = record.range(of: " path=") { return String(record[r.upperBound...]) }
        }
        return nil
    }
}
