import XCTest
import BCCrypto
import WolfBase

final class HashTests: XCTestCase {
    func testBlake2b() {
        let key = ‡"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        
        //
        // Keyed
        //
        
        /// From: https://github.com/BLAKE2/BLAKE2/blob/master/testvectors/blake2b-kat.txt
        XCTAssertEqual(BLAKE2b.hash(
            ‡"",
            key: key
        ), ‡"10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568")

        /// From: https://github.com/BLAKE2/BLAKE2/blob/master/testvectors/blake2b-kat.txt
        XCTAssertEqual(BLAKE2b.hash(
            ‡"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546474849",
            key: key
        ), ‡"dfb320c44f9d41d1efdcc015f08dd5539e526e39c87d509ae6812a969e5431bf4fa7d91ffd03b981e0d544cf72d7b1c0374f8801482e6dea2ef903877eba675e")

        //
        // Unkeyed
        //
        
        /// From: https://github.com/emilbayes/blake2b/blob/master/test-vectors.json
        XCTAssertEqual(BLAKE2b.hash(
            ‡""
        ), ‡"786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce")

        /// From: https://github.com/emilbayes/blake2b/blob/master/test-vectors.json
        XCTAssertEqual(BLAKE2b.hash(
            ‡"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"
        ), ‡"31a046f7882ffe6f83ce472e9a0701832ec7b3f76fbcfd1df60fe3ea48fde1651254247c3fd95e100f9172731e17fd5297c11f4bb328363ca361624a81af797c")
    }
    
    func testSHA() {
        let input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let digest256 = SHA256.hash(input.utf8Data)
        XCTAssertEqual(digest256.hex, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
        let digest512 = SHA512.hash(input.utf8Data)
        XCTAssertEqual(digest512.hex, "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445")
    }
    
    func testHMACSHA() {
        let key = ‡"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
        let message = "Hi There".utf8Data
        let hmac256 = SHA256.hmac(key: key, message: message)
        XCTAssertEqual(hmac256, ‡"b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        let hmac512 = SHA512.hmac(key: key, message: message)
        XCTAssertEqual(hmac512, ‡"87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854")
    }
    
    func testPBKDF2HMACSHA256() {
        let key = SHA256.pbkdf2HMAC(pass: "password".utf8Data, salt: "salt".utf8Data, iterations: 1, keyLen: 32)
        XCTAssertEqual(key, ‡"120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
    }
    
    func testHKDFHMACSHA256() {
        let message = "hello".utf8Data
        let salt = ‡"8e94ef805b93e683ff18"
        let key = SHA256.hkdfHMAC(keyMaterial: message, salt: salt, keyLen: 32)
        XCTAssertEqual(key, ‡"13485067e21af17c0900f70d885f02593c0e61e46f86450e4a0201a54c14db76")
    }

    func testCRC32() {
        let input = "Hello, world!".utf8Data
        let checksum = CRC32.hash(input)
        XCTAssertEqual(checksum, 0xebe6c6e6)
        XCTAssertEqual(CRC32.hashData(input), ‡"ebe6c6e6")
        XCTAssertEqual(CRC32.hashData(input, littleEndian: true), ‡"e6c6e6eb")
    }
    
    func testCRC32_2() {
        let string = "Wolf"
        let checksum = CRC32.hash(string.utf8Data)
        XCTAssertEqual(checksum, 0x598c84dc)
        XCTAssertEqual(checksum.serialized.hex, "598c84dc")
    }
    
    func testCRC32_3() {
        let data = ‡"916ec65cf77cadf55cd7f9cda1a1030026ddd42e905b77adc36e4f2d3ccba44f7f04f2de44f42d84c374a0e149136f25b01852545961d55f7f7a8cde6d0e2ec43f3b2dcb644a2209e8c9e34af5c4747984a5e873c9cf5f965e25ee29039fdf8ca74f1c769fc07eb7ebaec46e0695aea6cbd60b3ec4bbff1b9ffe8a9e7240129377b9d3711ed38d412fbb4442256f1e6f595e0fc57fed451fb0a0101fb76b1fb1e1b88cfdfdaa946294a47de8fff173f021c0e6f65b05c0a494e50791270a0050a73ae69b6725505a2ec8a5791457c9876dd34aadd192a53aa0dc66b556c0c215c7ceb8248b717c22951e65305b56a3706e3e86eb01c803bbf915d80edcd64d4d41977fa6f78dc07eecd072aae5bc8a852397e06034dba6a0b570797c3a89b16673c94838d884923b8186ee2db5c98407cab15e13678d072b43e406ad49477c2e45e85e52ca82a94f6df7bbbe7afbed3a3a830029f29090f25217e48d1f42993a640a67916aa7480177354cc7440215ae41e4d02eae9a191233a6d4922a792c1b7244aa879fefdb4628dc8b0923568869a983b8c661ffab9b2ed2c149e38d41fba090b94155adbed32f8b18142ff0d7de4eeef2b04adf26f2456b46775c6c20b37602df7da179e2332feba8329bbb8d727a138b4ba7a503215eda2ef1e953d89383a382c11d3f2cad37a4ee59a91236a3e56dcf89f6ac81dd4159989c317bd649d9cbc617f73fe10033bd288c60977481a09b343d3f676070e67da757b86de27bfca74392bac2996f7822a7d8f71a489ec6180390089ea80a8fcd6526413ec6c9a339115f111d78ef21d456660aa85f790910ffa2dc58d6a5b93705caef1091474938bd312427021ad1eeafbd19e0d916ddb111fabd8dcab5ad6a6ec3a9c6973809580cb2c164e26686b5b98cfb017a337968c7daaa14ae5152a067277b1b3902677d979f8e39cc2aafb3bc06fcf69160a853e6869dcc09a11b5009f91e6b89e5b927ab1527a735660faa6012b420dd926d940d742be6a64fb01cdc0cff9faa323f02ba41436871a0eab851e7f5782d10fbefde2a7e9ae9dc1e5c2c48f74f6c824ce9ef3c89f68800d44587bedc4ab417cfb3e7447d90e1e417e6e05d30e87239d3a5d1d45993d4461e60a0192831640aa32dedde185a371ded2ae15f8a93dba8809482ce49225daadfbb0fec629e23880789bdf9ed73be57fa84d555134630e8d0f7df48349f29869a477c13ccca9cd555ac42ad7f568416c3d61959d0ed568b2b81c7771e9088ad7fd55fd4386bafbf5a528c30f107139249357368ffa980de2c76ddd9ce4191376be0e6b5170010067e2e75ebe2d2904aeb1f89d5dc98cd4a6f2faaa8be6d03354c990fd895a97feb54668473e9d942bb99e196d897e8f1b01625cf48a7b78d249bb4985c065aa8cd1402ed2ba1b6f908f63dcd84b66425df"
        let checksum = CRC32.hash(data)
        XCTAssertEqual(checksum, 0x2f19f3bb)
    }
}
