import Foundation
import CryptoBase
import CryptoKit
import Blake2

/// Computes the Blake2b digest of the input buffer.
public func blake2b<D1, D2>(_ data: D1, key: D2?, len: Int = 64) -> Data
where D1: DataProtocol, D2: DataProtocol
{
    let dataPtr: any DataPtrRepresentable
    if let dataAsDataPtr = data as? (any DataPtrRepresentable) {
        dataPtr = dataAsDataPtr
    } else {
        dataPtr = Data(data)
    }
    if let keyAsDataPtr = key as? (any DataPtrRepresentable) {
        return try! Blake2b.hash(size: len, data: dataPtr, key: keyAsDataPtr)
    } else {
        if key == nil {
            return try! Blake2b.hash(size: len, data: dataPtr, key: nil as Data?)
        } else {
            return try! Blake2b.hash(size: len, data: dataPtr, key: Data(key!))
        }
    }
}

/// Computes the Blake2b digest of the input buffer.
public func blake2b<D>(_ data: D, len: Int = 64) -> Data
where D: DataProtocol
{
    return blake2b(data, key: nil as Data?, len: len)
}

/// Computes the SHA-256 digest of the input buffer.
public func sha256<D: DataProtocol>(_ data: D) -> Data {
    CryptoBase.sha256(data: Data(data))
}

/// Computes the SHA-512 digest of the input buffer.
public func sha512<D: DataProtocol>(_ data: D) -> Data {
    CryptoBase.sha512(data: Data(data))
}

/// Computes the HMAC-SHA-256 for the given key and message.
public func hmacSHA256<D1, D2>(key: D1, message: D2) -> Data
where D1: DataProtocol, D2: DataProtocol
{
    CryptoBase.hmacSHA256(key: Data(key), message: Data(message))
}

/// Computes the HMAC-SHA-512 for the given key and message.
public func hmacSHA512<D1, D2>(key: D1, message: D2) -> Data
where D1: DataProtocol, D2: DataProtocol
{
    CryptoBase.hmacSHA512(key: Data(key), message: Data(message))
}

/// Computes the PBKDF2-HMAC-SHA-256 for the given password.
public func pbkdf2HMACSHA256<D1, D2>(pass: D1, salt: D2, iterations: Int, keyLen: Int) -> Data
where D1: DataProtocol, D2: DataProtocol
{
    CryptoBase.pbkdf2HMACSHA256(pass: Data(pass), salt: Data(salt), iterations: iterations, keyLen: keyLen)
}

/// Computes the HKDF-HMAC-SHA-256 for the given key material.
@available(iOS 14.0, *)
@available(macOS 11.0, *)
public func hkdfHMACSHA256<D1, D2>(keyMaterial: D1, salt: D2, keyLen: Int) -> Data
where D1: DataProtocol, D2: DataProtocol
{
    HKDF<SHA256>.deriveKey(
        inputKeyMaterial: .init(data: Data(keyMaterial)),
        salt: Data(salt),
        outputByteCount: keyLen
    ).withUnsafeBytes {
        Data($0)
    }
}

/// Computes the CRC-32 checksum of the input buffer.
public func crc32<D: DataProtocol>(_ data: D) -> UInt32
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
public func crc32data<D: DataProtocol>(_ data: D, littleEndian: Bool = false) -> Data
{
    let n = crc32(data)
    var d = Data(repeating: 0, count: MemoryLayout<UInt32>.size)
    d.withUnsafeMutableBytes {
        let v = littleEndian ? n.littleEndian : n.bigEndian
        $0.bindMemory(to: UInt32.self).baseAddress!.pointee = v
    }
    return d
}
