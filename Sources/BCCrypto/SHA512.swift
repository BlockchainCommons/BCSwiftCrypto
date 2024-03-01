import Foundation
import CryptoBase

public enum SHA512 {
    public static let digestSize = 64
    
    /// Computes the SHA-512 digest of the input buffer.
    public static func hash<D: DataProtocol>(_ data: D) -> Data {
        CryptoBase.sha512(data: Data(data))
    }
    
    /// Computes the HMAC-SHA-512 for the given key and message.
    public static func hmac<D1, D2>(key: D1, message: D2) -> Data
    where D1: DataProtocol, D2: DataProtocol
    {
        CryptoBase.hmacSHA512(key: Data(key), message: Data(message))
    }
}
