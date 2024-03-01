import XCTest
import BCCrypto
import WolfBase
import BCRandom

// Test vector from: https://datatracker.ietf.org/doc/html/rfc8439#section-2.8.2
fileprivate let plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".utf8Data
fileprivate let aad = ‡"50515253c0c1c2c3c4c5c6c7"
fileprivate let key = ‡"808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
fileprivate let nonce = ‡"070000004041424344454647"
fileprivate let encrypted = try! AEADChaCha20Poly1305.encrypt(plaintext: plaintext, key: key, nonce: nonce, aad: aad)
fileprivate let ciphertext = ‡"d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"
fileprivate let auth = ‡"1ae10b594f09e26a7e902ecbd0600691"

class AEADChaCha20Poly1305Tests: XCTestCase {
    func testRFCTestVector() throws {
        XCTAssertEqual(encrypted.ciphertext, ciphertext)
        XCTAssertEqual(encrypted.auth, auth)
        
        let decryptedPlaintext = try AEADChaCha20Poly1305.decrypt(ciphertext: ciphertext, key: key, nonce: nonce, aad: aad, auth: encrypted.auth)
        XCTAssertEqual(plaintext, decryptedPlaintext)
    }
    
    func testRandomKeyAndNonce() throws {
        let key = secureRandomData(32)
        let nonce = secureRandomData(12)
        let (ciphertext, auth) = try AEADChaCha20Poly1305.encrypt(plaintext: plaintext, key: key, nonce: nonce, aad: aad)
        let decryptedPlaintext = try AEADChaCha20Poly1305.decrypt(ciphertext: ciphertext, key: key, nonce: nonce, aad: aad, auth: auth)
        XCTAssertEqual(plaintext, decryptedPlaintext)
    }

    func testEmptyData() throws {
        let key = secureRandomData(32)
        let nonce = secureRandomData(12)
        let (ciphertext, auth) = try AEADChaCha20Poly1305.encrypt(plaintext: Data(), key: key, nonce: nonce)
        let decryptedPlaintext = try AEADChaCha20Poly1305.decrypt(ciphertext: ciphertext, key: key, nonce: nonce, auth: auth)
        XCTAssertEqual(Data(), decryptedPlaintext)
    }
}
