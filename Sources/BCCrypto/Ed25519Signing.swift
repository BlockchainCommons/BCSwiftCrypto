import Foundation
import CryptoKit

public func ed25519Sign<D1, D2>(privateKey key: D1, message: D2) -> Data
where D1: DataProtocol, D2: DataProtocol {
    let privateKey = try! Curve25519.Signing.PrivateKey(rawRepresentation: Data(key))
    return try! privateKey.signature(for: Data(message))
}

public func ed25519Verify<D1, D2, D3>(publicKey: D1, signature: D2, message: D3) -> Bool
where D1: DataProtocol, D2: DataProtocol, D3: DataProtocol {
    let publicKey = try! Curve25519.Signing.PublicKey(rawRepresentation: Data(publicKey))
    return publicKey.isValidSignature(Data(signature), for: Data(message))
}
