import Testing
import BCCrypto
import WolfBase
import BCRandom

struct Ed25519KeysTests {
    @Test func testEd25519Keys() {
        var rng = makeFakeRandomNumberGenerator()
        let privateKey = Ed25519.newPrivateKey(using: &rng)
        #expect(privateKey == ‡"7eb559bbbf6cce2632cf9f194aeb50943de7e1cbad54dcfab27a42759f5e2fed")
        let publicKey = Ed25519.derivePublicKey(privateKey: privateKey)
        #expect(publicKey == ‡"76f863e1024d8ff6cd8ad56c434e01dbbf2999cfc2f132fc7f41ca19fed7a97c")
    }

    @Test func testEd25519Signing() {
        var rng = makeFakeRandomNumberGenerator()
        let privateKey = Ed25519.newPrivateKey(using: &rng)
        let message = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".utf8Data
        
        let publicKey = Ed25519.derivePublicKey(privateKey: privateKey)
        let signature = Ed25519.sign(privateKey: privateKey, message: message)
        // The signature cannot be compared exactly here, because CryptoKit
        // uses randomization we cannot control.
        #expect(Ed25519.verify(publicKey: publicKey, signature: signature, message: message))
    }
}
