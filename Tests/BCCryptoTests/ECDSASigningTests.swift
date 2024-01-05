import XCTest
import BCCrypto
import WolfBase

final class ECDSASigningTests: XCTestCase {
    func testECDSASigning() {
        var rng = makeFakeRandomNumberGenerator()
        let privateKey = ecdsaNewPrivateKey(using: &rng)
        let message = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".utf8Data
        
        let ecdsaPublicKey = ecdsaPublicKeyFromPrivateKey(privateKey: privateKey)
        let ecdsaSignature = ecdsaSign(privateKeyECDSA: privateKey, message: message)
        XCTAssertEqual(ecdsaSignature, ‡"e75702ed8f645ce7fe510507b2403029e461ef4570d12aa440e4f81385546a13740b7d16878ff0b46b1cbe08bc218ccb0b00937b61c4707de2ca6148508e51fb")
        XCTAssertTrue(ecdsaVerify(publicKeyECDSA: ecdsaPublicKey, signature: ecdsaSignature, message: message))
    }
}
