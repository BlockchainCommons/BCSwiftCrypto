import Foundation

public enum CryptoError: Error {
    case invalidAuthentication
    case invalidPublicKey
    case invalidPrivateKey
    case invalidSignature
}
