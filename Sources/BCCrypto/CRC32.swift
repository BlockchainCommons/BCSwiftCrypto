import Foundation
import CryptoBase

public enum CRC32 {
    /// Computes the CRC-32 checksum of the input buffer.
    public static func hash<D: DataProtocol>(_ data: D) -> UInt32
    {
        CryptoBase.crc32(data: Data(data))
    }
    
    /// Returns the CRC-32 checksum of the input buffer, as a buffer.
    ///
    /// - Parameters:
    ///   - data: The input buffer.
    ///   - littleEndian: `false` if the returned `Data` is to be in network byte order
    ///   (big endian) or `true` if in little endian order.
    /// - Returns: `Data` containing the 4-byte long checksum in the specified order.
    public static func hashData<D: DataProtocol>(_ data: D, littleEndian: Bool = false) -> Data
    {
        let n = hash(data)
        var d = Data(repeating: 0, count: MemoryLayout<UInt32>.size)
        d.withUnsafeMutableBytes {
            let v = littleEndian ? n.littleEndian : n.bigEndian
            $0.bindMemory(to: UInt32.self).baseAddress!.pointee = v
        }
        return d
    }
}
