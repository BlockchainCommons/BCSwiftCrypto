import XCTest
import BCCrypto
import WolfBase

final class LibSecp256k1Tests: XCTestCase {
    func testTaggedSHA256() {
        let taggedHash = LibSecP256K1.taggedSHA256(msg: "Hello".utf8Data, tag: "World".utf8Data)
        XCTAssertEqual(taggedHash, ‡"e9f3a975986209830c6797c0e3fda21545360d2055c96b5386b5c5ab7c0cf53e")
    }
}
