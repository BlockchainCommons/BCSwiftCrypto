import XCTest
import BCCrypto
import WolfBase

final class Ed25519SigningTests: XCTestCase {
    func testEd25519Signing() {
        var rng = makeFakeRandomNumberGenerator()
        let privateKey = ed25519NewPrivateKey(using: &rng)
        let message = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".utf8Data
        
        let publicKey = ed25519PublicKeyFromPrivateKey(privateKey: privateKey)
        let signature = ed25519Sign(privateKey: privateKey, message: message)
        // The signature cannot be compared exactly here, because CryptoKit
        // uses randomization we cannot control.
        XCTAssertTrue(ed25519Verify(publicKey: publicKey, signature: signature, message: message))
    }
}
