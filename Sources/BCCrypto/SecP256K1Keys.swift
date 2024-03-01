import Foundation
import BCWally

public let secp256k1PrivateKeySize = 32
public let secp256k1PublicKeySize = 33
public let secp256k1PublicKeyUncompressedSize = 65

public func secp256k1NewPrivateKey() -> Data {
    var rng = SecureRandomNumberGenerator()
    return secp256k1NewPrivateKey(using: &rng)
}

public func secp256k1NewPrivateKey<T>(using rng: inout T) -> Data
    where T: RandomNumberGenerator
{
    return rng.randomData(32)
}

public func secp256k1PublicKeyFromPrivateKey<D: DataProtocol>(privateKey: D) -> Data {
    Wally.ecPublicKeyFromPrivateKey(data: Data(privateKey))
}

public func secp256k1DecompressPublicKey<D: DataProtocol>(compressedPublicKey: D) -> Data {
    Wally.ecPublicKeyDecompress(data: Data(compressedPublicKey))
}

public func secp256k1CompressPublicKey<D: DataProtocol>(uncompressedPublicKey: D) -> Data {
    let data = Data(uncompressedPublicKey)
    precondition(data.count == 65)
    precondition(data[0] == 0x04)

    let x = data[1...32]
    let y = data[33...64]

    if y.last! % 2 == 0 {
        return Data([0x02]) + x
    } else {
        return Data([0x03]) + x
    }
}

public func secp256k1DerivePrivateKey<D: DataProtocol>(keyMaterial: D) -> Data {
    hkdfHMACSHA256(keyMaterial: keyMaterial, salt: "signing".utf8Data, keyLen: 32)
}

public func secp256k1SchnorrPublicKeyFromPrivateKey<D: DataProtocol>(privateKey: D) -> Data {
    let kp = LibSecP256K1.keyPair(from: Data(privateKey))!
    let x = LibSecP256K1.schnorrPublicKey(from: kp)
    return LibSecP256K1.serialize(key: x)
}
