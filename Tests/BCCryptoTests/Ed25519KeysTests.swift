import XCTest
import BCCrypto
import WolfBase

final class Ed25519KeysTests: XCTestCase {
    func testEd25519Keys() {
        var rng = makeFakeRandomNumberGenerator()
        let privateKey = ed25519NewPrivateKey(using: &rng)
        XCTAssertEqual(privateKey, ‡"7eb559bbbf6cce2632cf9f194aeb50943de7e1cbad54dcfab27a42759f5e2fed")
        let publicKey = ed25519PublicKeyFromPrivateKey(privateKey: privateKey)
        XCTAssertEqual(publicKey, ‡"76f863e1024d8ff6cd8ad56c434e01dbbf2999cfc2f132fc7f41ca19fed7a97c")
    }
}
