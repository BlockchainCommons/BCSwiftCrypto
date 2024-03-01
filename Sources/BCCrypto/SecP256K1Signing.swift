import Foundation

public func secp256k1ecdsaSign<D1, D2>(privateKeySecP256K1 key: D1, message: D2) -> Data
where D1: DataProtocol, D2: DataProtocol
{
    LibSecP256K1.ecdsaSign(message: Data(message), secKey: Data(key))
}

public func secp256k1Verify<D1, D2, D3>(publicKeySecP256K1 publicKey: D1, signature: D2, message: D3) -> Bool
where D1: DataProtocol, D2: DataProtocol, D3: DataProtocol
{
    precondition(signature.count == 64)
    let signature = LibSecP256K1.ecdsaSignature(from: Data(signature))!
    let publicKey = LibSecP256K1.ecPublicKey(from: Data(publicKey))!
    return LibSecP256K1.ecdsaVerify(message: Data(message), signature: signature, publicKey: publicKey)
}
