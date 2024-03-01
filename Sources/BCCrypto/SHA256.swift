import Foundation
import CryptoBase
import CryptoKit

public enum SHA256 {
    public static let digestSize = 32
    
    /// Computes the SHA-256 digest of the input buffer.
    public static func hash<D: DataProtocol>(_ data: D) -> Data {
        CryptoBase.sha256(data: Data(data))
    }
    
    /// Computes the HMAC-SHA-256 for the given key and message.
    public static func hmac<D1, D2>(key: D1, message: D2) -> Data
    where D1: DataProtocol, D2: DataProtocol
    {
        CryptoBase.hmacSHA256(key: Data(key), message: Data(message))
    }
    
    /// Computes the PBKDF2-HMAC-SHA-256 for the given password.
    public static func pbkdf2HMAC<D1, D2>(pass: D1, salt: D2, iterations: Int, keyLen: Int) -> Data
    where D1: DataProtocol, D2: DataProtocol
    {
        CryptoBase.pbkdf2HMACSHA256(pass: Data(pass), salt: Data(salt), iterations: iterations, keyLen: keyLen)
    }
    
    /// Computes the HKDF-HMAC-SHA-256 for the given key material.
    @available(iOS 14.0, *)
    @available(macOS 11.0, *)
    public static func hkdfHMAC<D1, D2>(keyMaterial: D1, salt: D2, keyLen: Int) -> Data
    where D1: DataProtocol, D2: DataProtocol
    {
        HKDF<CryptoKit.SHA256>.deriveKey(
            inputKeyMaterial: .init(data: Data(keyMaterial)),
            salt: Data(salt),
            outputByteCount: keyLen
        ).withUnsafeBytes {
            Data($0)
        }
    }
}
