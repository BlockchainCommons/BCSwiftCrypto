import Foundation
import CryptoKit

public enum Ed25519 {
    public static let privateKeySize = 32
    public static let publicKeySize = 32
}

public extension Ed25519 {
    static func newPrivateKey() -> Data {
        var rng = SecureRandomNumberGenerator()
        return newPrivateKey(using: &rng)
    }
    
    static func newPrivateKey<T>(using rng: inout T) -> Data
    where T: RandomNumberGenerator
    {
        return rng.randomData(privateKeySize)
    }
    
    static func derivePrivateKey<D: DataProtocol>(keyMaterial: D) -> Data {
        SHA256.hkdfHMAC(keyMaterial: keyMaterial, salt: "signing".utf8Data, keyLen: privateKeySize)
    }
}

public extension Ed25519 {
    static func derivePublicKey<D: DataProtocol>(privateKey: D) -> Data {
        let privateKey = try! Curve25519.Signing.PrivateKey(rawRepresentation: Data(privateKey))
        let publicKey = privateKey.publicKey
        return publicKey.rawRepresentation
    }
}

public extension Ed25519 {
    static func sign<D1, D2>(privateKey key: D1, message: D2) -> Data
    where D1: DataProtocol, D2: DataProtocol {
        let privateKey = try! Curve25519.Signing.PrivateKey(rawRepresentation: Data(key))
        return try! privateKey.signature(for: Data(message))
    }
    
    static func verify<D1, D2, D3>(publicKey: D1, signature: D2, message: D3) -> Bool
    where D1: DataProtocol, D2: DataProtocol, D3: DataProtocol {
        let publicKey = try! Curve25519.Signing.PublicKey(rawRepresentation: Data(publicKey))
        return publicKey.isValidSignature(Data(signature), for: Data(message))
    }
}
