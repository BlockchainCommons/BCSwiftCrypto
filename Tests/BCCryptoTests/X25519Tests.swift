import Testing
import BCCrypto
import WolfBase
import BCRandom

struct X25519Tests {
    @Test func testX25519Keys() {
        var rng = makeFakeRandomNumberGenerator()
        let privateKey = X25519.newAgreementPrivateKey(using: &rng)
        #expect(privateKey == ‡"7eb559bbbf6cce2632cf9f194aeb50943de7e1cbad54dcfab27a42759f5e2fed")
        let publicKey = X25519.deriveAgreementPublicKey(agreementPrivateKey: privateKey)
        #expect(publicKey == ‡"f1bd7a7e118ea461eba95126a3efef543ebb78439d1574bedcbe7d89174cf025")
        
        let derivedAgreementPrivateKey = X25519.deriveAgreementPrivateKey(keyMaterial: "password".utf8Data)
        #expect(derivedAgreementPrivateKey == ‡"7b19769132648ff43ae60cbaa696d5be3f6d53e6645db72e2d37516f0729619f")
    }
    
    @Test func testKeyAgreement() {
        var rng = makeFakeRandomNumberGenerator()
        let alicePrivateKey = X25519.newAgreementPrivateKey(using: &rng)
        let alicePublicKey = X25519.deriveAgreementPublicKey(agreementPrivateKey: alicePrivateKey)
        let bobPrivateKey = X25519.newAgreementPrivateKey(using: &rng)
        let bobPublicKey = X25519.deriveAgreementPublicKey(agreementPrivateKey: bobPrivateKey)
        let aliceSharedKey = X25519.deriveAgreementSharedKey(agreementPrivateKey: alicePrivateKey, agreementPublicKey: bobPublicKey)
        let bobSharedKey = X25519.deriveAgreementSharedKey(agreementPrivateKey: bobPrivateKey, agreementPublicKey: alicePublicKey)
        #expect(aliceSharedKey == bobSharedKey)
        #expect(aliceSharedKey == ‡"1e9040d1ff45df4bfca7ef2b4dd2b11101b40d91bf5bf83f8c83d53f0fbb6c23")
    }
}
