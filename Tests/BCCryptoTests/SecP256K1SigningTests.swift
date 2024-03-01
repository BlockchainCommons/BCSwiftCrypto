import XCTest
import BCCrypto
import WolfBase

final class SecP256K1SigningTests: XCTestCase {
    func testSecP256K1Signing() {
        var rng = makeFakeRandomNumberGenerator()
        let privateKey = secp256k1NewPrivateKey(using: &rng)
        let message = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".utf8Data
        
        let secp256k1PublicKey = secp256k1PublicKeyFromPrivateKey(privateKey: privateKey)
        let secp256k1Signature = secp256k1ecdsaSign(privateKeySecP256K1: privateKey, message: message)
        XCTAssertEqual(secp256k1Signature, ‡"e75702ed8f645ce7fe510507b2403029e461ef4570d12aa440e4f81385546a13740b7d16878ff0b46b1cbe08bc218ccb0b00937b61c4707de2ca6148508e51fb")
        XCTAssertTrue(secp256k1Verify(publicKeySecP256K1: secp256k1PublicKey, signature: secp256k1Signature, message: message))
    }
}
