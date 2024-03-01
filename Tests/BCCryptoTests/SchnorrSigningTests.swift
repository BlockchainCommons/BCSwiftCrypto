import XCTest
import BCCrypto
import WolfBase

final class SchnorrSigningTests: XCTestCase {
    func testTaggedSHA256() {
        let taggedHash = LibSecP256K1.taggedSHA256(msg: "Hello".utf8Data, tag: "World".utf8Data)
        XCTAssertEqual(taggedHash, ‡"e9f3a975986209830c6797c0e3fda21545360d2055c96b5386b5c5ab7c0cf53e")
    }
    
    func testSchnorrSign() {
        var rng = makeFakeRandomNumberGenerator()
        let privateKey = secp256k1NewPrivateKey(using: &rng)
        XCTAssertEqual(privateKey, ‡"7eb559bbbf6cce2632cf9f194aeb50943de7e1cbad54dcfab27a42759f5e2fed")
        let message = "Hello".utf8Data
        let tag = "World".utf8Data
        let signature = secp256k1schnorrSign(secp256k1PrivateKey: privateKey, message: message, tag: tag, rng: &rng)
        XCTAssertEqual(signature, ‡"d7488b8f2107c468b4c75a59f9cf1f9945fe7742229a186baa005dcfd434720183958fde5aa34045fea71793710e56b160cf74400b90580ed58ce95d8fa92b45")
        let schnorrPublicKey = secp256k1SchnorrPublicKeyFromPrivateKey(privateKey: privateKey)
        XCTAssertTrue(secp256k1schnorrVerify(schnorrPublicKey: schnorrPublicKey, signature: signature, message: message, tag: tag))
    }
}
