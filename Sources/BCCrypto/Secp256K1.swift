import Foundation
import BCWally
import BCRandom

public enum Secp256k1 {
    public static let privateKeySize = 32
    public static let publicKeySize = 33
    public static let uncompressedPublicKeySize = 65
    
    public enum ECDSA { }
    public enum Schnorr { }
}

public extension Secp256k1 {
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

public extension Secp256k1.ECDSA {
    static func derivePublicKey<D: DataProtocol>(privateKey: D) -> Data {
        Wally.ecPublicKeyFromPrivateKey(data: Data(privateKey))
    }
    
    static func uncompressPublicKey<D: DataProtocol>(compressedPublicKey: D) -> Data {
        Wally.ecPublicKeyDecompress(data: Data(compressedPublicKey))
    }
    
    static func compressPublicKey<D: DataProtocol>(uncompressedPublicKey: D) -> Data {
        let data = Data(uncompressedPublicKey)
        precondition(data.count == Secp256k1.uncompressedPublicKeySize)
        precondition(data[0] == 0x04)
        
        let x = data[1...32]
        let y = data[33...64]
        
        if y.last! % 2 == 0 {
            return Data([0x02]) + x
        } else {
            return Data([0x03]) + x
        }
    }
    
    static func sign<D1, D2>(privateKey: D1, message: D2) -> Data
    where D1: DataProtocol, D2: DataProtocol
    {
        LibSecP256K1.ecdsaSign(message: Data(message), secKey: Data(privateKey))
    }
    
    static func verify<D1, D2, D3>(publicKey: D1, signature: D2, message: D3) throws -> Bool
    where D1: DataProtocol, D2: DataProtocol, D3: DataProtocol
    {
        guard
            signature.count == 64,
            let signature = LibSecP256K1.ecdsaSignature(from: Data(signature))
        else {
            throw CryptoError.invalidSignature
        }
        guard let publicKey = LibSecP256K1.ecPublicKey(from: Data(publicKey)) else {
            throw CryptoError.invalidPublicKey
        }
        return LibSecP256K1.ecdsaVerify(message: Data(message), signature: signature, publicKey: publicKey)
    }
}

public extension Secp256k1.Schnorr {
    static func derivePublicKey<D: DataProtocol>(privateKey: D) throws -> Data {
        guard let kp = LibSecP256K1.keyPair(from: Data(privateKey)) else {
            throw CryptoError.invalidPrivateKey
        }
        let x = LibSecP256K1.schnorrPublicKey(from: kp)
        return LibSecP256K1.serialize(key: x)
    }
    
    static func sign<D1, D2>(
        privateKey: D1,
        message: D2
    ) throws -> Data
    where D1: DataProtocol, D2: DataProtocol
    {
        guard let kp = LibSecP256K1.keyPair(from: Data(privateKey)) else {
            throw CryptoError.invalidPrivateKey
        }
        return LibSecP256K1.schnorrSign(keyPair: kp, msg: Data(message))
    }
    
    static func signUsing<D1, D2, T>(
        privateKey: D1,
        message: D2,
        rng: inout T
    ) throws -> Data
    where D1: DataProtocol, D2: DataProtocol, T: RandomNumberGenerator
    {
        guard let kp = LibSecP256K1.keyPair(from: Data(privateKey)) else {
            throw CryptoError.invalidPrivateKey
        }
        return LibSecP256K1.schnorrSignUsing(keyPair: kp, msg: Data(message), rng: &rng)
    }
    
    static func signWithAuxRand<D1, D2, D3>(
        privateKey: D1,
        message: D2,
        auxRand: D3
    ) throws -> Data
    where D1: DataProtocol, D2: DataProtocol, D3: DataProtocol
    {
        guard let kp = LibSecP256K1.keyPair(from: Data(privateKey)) else {
            throw CryptoError.invalidPrivateKey
        }
        return LibSecP256K1.schnorrSignWithAuxRand(
            keyPair: kp,
            msg: Data(message),
            auxRand: Data(auxRand)
        )
    }
    
    static func verify<D1, D2, D3>(
        schnorrPublicKey: D1,
        signature: D2,
        message: D3
    ) throws -> Bool
    where D1: DataProtocol, D2: DataProtocol, D3: DataProtocol
    {
        guard let publicKey = LibSecP256K1.schnorrPublicKey(from: Data(schnorrPublicKey)) else {
            throw CryptoError.invalidPublicKey
        }
        return LibSecP256K1.schnorrVerify(publicKey: publicKey, signature: Data(signature), msg: Data(message))
    }
}
