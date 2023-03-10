import Foundation
import BCWally

public extension Crypto {
    static let privateKeyLenECDSA = Int(EC_PRIVATE_KEY_LEN)
    static let publicKeyLenECDSA = Int(EC_PUBLIC_KEY_LEN)
    static let publicKeyUncompressedLenECDSA = Int(EC_PUBLIC_KEY_UNCOMPRESSED_LEN)
    
    static func newPrivateKeyECDSA() -> Data {
        randomData(count: 32)
    }
    
    static func publicKeyFromPrivateKeyECDSA<D: DataProtocol>(privateKey: D) -> Data {
        Wally.ecPublicKeyFromPrivateKey(data: Data(privateKey))
    }
    
    static func decompressPublicKeyECDSA<D: DataProtocol>(compressedPublicKey: D) -> Data {
        Wally.ecPublicKeyDecompress(data: Data(compressedPublicKey))
    }
    
    static func compressPublicKeyECDSA<D: DataProtocol>(decompressedPublicKey: D) -> Data {
        Wally.ecPublicKeyCompress(data: Data(decompressedPublicKey))
    }
    
    static func derivePrivateKeyECDSA<D: DataProtocol>(keyMaterial: D) -> Data {
        hkdfHMACSHA256(keyMaterial: keyMaterial, salt: "signing".utf8Data, keyLen: 32)
    }
}
