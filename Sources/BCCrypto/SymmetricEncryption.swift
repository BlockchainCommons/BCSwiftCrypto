import Foundation
import CryptoSwift

public extension Crypto {
    static func aeadChaCha20Poly1305Encrypt<D1, D2, D3, D4>(plaintext: D1, key: D2, nonce: D3, aad: D4) throws -> (ciphertext: Data, auth: Data)
    where D1: DataProtocol, D2: DataProtocol, D3: DataProtocol, D4: DataProtocol
    {
        let (ciphertext, auth) = try AEADChaCha20Poly1305.encrypt(
            Data(plaintext).bytes,
            key: Data(key).bytes,
            iv: Data(nonce).bytes,
            authenticationHeader: Data(aad).bytes
        )
        return (Data(ciphertext), Data(auth))
    }
    
    static func aeadChaCha20Poly1305Encrypt<D1, D2, D3>(plaintext: D1, key: D2, nonce: D3) throws -> (ciphertext: Data, auth: Data)
    where D1: DataProtocol, D2: DataProtocol, D3: DataProtocol
    {
        try aeadChaCha20Poly1305Encrypt(
            plaintext: plaintext,
            key: key,
            nonce: nonce,
            aad: Data()
        )
    }
    
    static func aeadChaCha20Poly1305Decrypt<D1, D2, D3, D4, D5>(ciphertext: D1, key: D2, nonce: D3, aad: D4, auth: D5) throws -> Data
    where D1: DataProtocol, D2: DataProtocol, D3: DataProtocol, D4: DataProtocol, D5: DataProtocol
    {
        switch try AEADChaCha20Poly1305.decrypt(
            Data(ciphertext).bytes,
            key: Data(key).bytes,
            iv: Data(nonce).bytes,
            authenticationHeader: Data(aad).bytes,
            authenticationTag: Data(auth).bytes
        ) {
        case (_, false):
            throw Error.invalidAuthentication
        case (let plaintext, true):
            return Data(plaintext)
        }
    }
    
    static func aeadChaCha20Poly1305Decrypt<D1, D2, D3, D4>(ciphertext: D1, key: D2, nonce: D3, auth: D4) throws -> Data
    where D1: DataProtocol, D2: DataProtocol, D3: DataProtocol, D4: DataProtocol, D4: DataProtocol
    {
        try aeadChaCha20Poly1305Decrypt(ciphertext: ciphertext, key: key, nonce: nonce, aad: Data(), auth: auth)
    }
}
