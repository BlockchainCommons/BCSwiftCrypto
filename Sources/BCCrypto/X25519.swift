import Foundation
import CryptoKit
import BCRandom

public enum X25519 {
    public static let agreementPrivateKeySize = 32
    public static let agreementPublicKeySize = 32
    public static let agreementSharedKeySize = 32
}

public extension X25519 {
    static func newAgreementPrivateKey() -> Data {
        var rng = SecureRandomNumberGenerator()
        return newAgreementPrivateKey(using: &rng)
    }
    
    static func newAgreementPrivateKey<T>(using rng: inout T) -> Data
    where T: RandomNumberGenerator
    {
        return rng.randomData(agreementPrivateKeySize)
    }
    
    static func deriveAgreementPrivateKey<D: DataProtocol>(keyMaterial: D) -> Data {
        SHA256.hkdfHMAC(keyMaterial: keyMaterial, salt: "agreement".utf8Data, keyLen: agreementPrivateKeySize)
    }

    static func deriveAgreementPublicKey<D: DataProtocol>(agreementPrivateKey: D) -> Data {
        try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(agreementPrivateKey)).publicKey.rawRepresentation
    }
    
    static func deriveAgreementSharedKey<D1, D2>(agreementPrivateKey: D1, agreementPublicKey: D2) -> Data
    where D1: DataProtocol, D2: DataProtocol {
        let agreementPrivateKey = try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(agreementPrivateKey))
        let agreementPublicKey = try! Curve25519.KeyAgreement.PublicKey(rawRepresentation: Data(agreementPublicKey))
        let sharedSecret = try! agreementPrivateKey.sharedSecretFromKeyAgreement(with: agreementPublicKey)
        return sharedSecret.hkdfDerivedSymmetricKey(
            using: CryptoKit.SHA256.self,
            salt: "agreement".utf8Data,
            sharedInfo: Data(),
            outputByteCount: agreementSharedKeySize
        ).withUnsafeBytes {
            Data($0)
        }
    }
}
