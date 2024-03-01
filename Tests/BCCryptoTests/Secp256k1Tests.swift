import XCTest
import BCCrypto
import WolfBase
import BCRandom

final class Secp256k1Tests: XCTestCase {
    func testKeys() {
        var rng = makeFakeRandomNumberGenerator()
        let privateKey = Secp256k1.newPrivateKey(using: &rng)
        XCTAssertEqual(privateKey, ‡"7eb559bbbf6cce2632cf9f194aeb50943de7e1cbad54dcfab27a42759f5e2fed")
        let publicKey = Secp256k1.ECDSA.derivePublicKey(privateKey: privateKey)
        XCTAssertEqual(publicKey, ‡"0271b92b6212a79b9215f1d24efb9e6294a1bedc95b6c8cf187cb94771ca02626b")
        
        let decompressed = Secp256k1.ECDSA.uncompressPublicKey(compressedPublicKey: publicKey)
        XCTAssertEqual(decompressed, ‡"0471b92b6212a79b9215f1d24efb9e6294a1bedc95b6c8cf187cb94771ca02626b72325f1f3bb69a44d3f1cb6d1fd488220dd502f49c0b1a46cb91ce3718d8334a")
        
        let compressed = Secp256k1.ECDSA.compressPublicKey(uncompressedPublicKey: decompressed)
        XCTAssertEqual(compressed, publicKey)
        
        let xOnly = Secp256k1.Schnorr.derivePublicKey(privateKey: privateKey)
        XCTAssertEqual(xOnly, ‡"71b92b6212a79b9215f1d24efb9e6294a1bedc95b6c8cf187cb94771ca02626b")
        
        let derivedPrivateKey = Secp256k1.derivePrivateKey(keyMaterial: "password".utf8Data)
        XCTAssertEqual(derivedPrivateKey, ‡"05cc550daa75058e613e606d9898fedf029e395911c43273a208b7e0e88e271b")
    }
    
    func testECDSASigning() {
        var rng = makeFakeRandomNumberGenerator()
        let privateKey = Secp256k1.newPrivateKey(using: &rng)
        let message = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".utf8Data
        
        let secp256k1PublicKey = Secp256k1.ECDSA.derivePublicKey(privateKey: privateKey)
        let secp256k1Signature = Secp256k1.ECDSA.sign(privateKey: privateKey, message: message)
        XCTAssertEqual(secp256k1Signature, ‡"e75702ed8f645ce7fe510507b2403029e461ef4570d12aa440e4f81385546a13740b7d16878ff0b46b1cbe08bc218ccb0b00937b61c4707de2ca6148508e51fb")
        XCTAssertTrue(Secp256k1.ECDSA.verify(publicKey: secp256k1PublicKey, signature: secp256k1Signature, message: message))
    }

    func testSchnorrSign() {
        var rng = makeFakeRandomNumberGenerator()
        let privateKey = Secp256k1.newPrivateKey(using: &rng)
        XCTAssertEqual(privateKey, ‡"7eb559bbbf6cce2632cf9f194aeb50943de7e1cbad54dcfab27a42759f5e2fed")
        let message = "Hello".utf8Data
        let tag = "World".utf8Data
        let signature = Secp256k1.Schnorr.sign(privateKey: privateKey, message: message, tag: tag, rng: &rng)
        XCTAssertEqual(signature, ‡"d7488b8f2107c468b4c75a59f9cf1f9945fe7742229a186baa005dcfd434720183958fde5aa34045fea71793710e56b160cf74400b90580ed58ce95d8fa92b45")
        let schnorrPublicKey = Secp256k1.Schnorr.derivePublicKey(privateKey: privateKey)
        XCTAssertTrue(Secp256k1.Schnorr.verify(schnorrPublicKey: schnorrPublicKey, signature: signature, message: message, tag: tag))
    }
}
