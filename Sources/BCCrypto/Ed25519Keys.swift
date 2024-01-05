import Foundation
import CryptoKit

public let ed25519PrivateKeySize = 32
public let ed25519PublicKeySize = 32

public func ed25519NewPrivateKey() -> Data {
    var rng = SecureRandomNumberGenerator()
    return ed25519NewPrivateKey(using: &rng)
}

public func ed25519NewPrivateKey<T>(using rng: inout T) -> Data
    where T: RandomNumberGenerator
{
    return rng.randomData(32)
}

public func ed25519PublicKeyFromPrivateKey<D: DataProtocol>(privateKey: D) -> Data {
    let privateKey = try! Curve25519.Signing.PrivateKey(rawRepresentation: Data(privateKey))
    let publicKey = privateKey.publicKey
    return publicKey.rawRepresentation
}

public func ed25519DerivePrivateKey<D: DataProtocol>(keyMaterial: D) -> Data {
    hkdfHMACSHA256(keyMaterial: keyMaterial, salt: "signing".utf8Data, keyLen: 32)
}
