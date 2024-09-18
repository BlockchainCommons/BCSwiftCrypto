import Foundation
import BCRandom
import secp256k1

public enum LibSecP256K1 {
}

public extension LibSecP256K1 {
    static func keyPair(from secretKey: Data) -> secp256k1_keypair? {
        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN))!
        defer { secp256k1_context_destroy(context) }
        
        var keypair = secp256k1_keypair()
        let result: Int32 = secretKey.withUnsafeByteBuffer { secretKey in
            return secp256k1_keypair_create(context, &keypair, secretKey.baseAddress!)
        }
        guard result == 1 else {
            return nil
        }
        return keypair
    }
}

public extension LibSecP256K1 {
    static func ecPublicKey(from serialized: Data) -> secp256k1_pubkey? {
        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_NONE))!
        defer { secp256k1_context_destroy(context) }

        var pubKey = secp256k1_pubkey()
        let serializedCount = serialized.count
        let result: Int32 = serialized.withUnsafeByteBuffer { serialized in
            secp256k1_ec_pubkey_parse(context, &pubKey, serialized.baseAddress!, serializedCount)
        }
        guard result == 1 else {
            return nil
        }
        return pubKey
    }
    
    static func serialize(key: secp256k1_pubkey) -> Data {
        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_NONE))!
        defer { secp256k1_context_destroy(context) }
        
        var serialized_count = 33
        var serialized = Data(repeating: 0, count: serialized_count)

        serialized.withUnsafeMutableByteBuffer { serialized in
            withUnsafePointer(to: key) { key in
                _ = secp256k1_ec_pubkey_serialize(context, serialized.baseAddress!, &serialized_count, key, UInt32(SECP256K1_EC_COMPRESSED))
            }
        }
        return serialized
    }
    
    static func publicKey(from keyPair: secp256k1_keypair) -> secp256k1_pubkey {
        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_NONE))!
        defer { secp256k1_context_destroy(context) }

        var pubKey = secp256k1_pubkey()
        withUnsafePointer(to: keyPair) { keyPair in
            _ = secp256k1_keypair_pub(context, &pubKey, keyPair);
        }
        return pubKey
    }
    
    static func doubleSHA256(message: Data) -> Data {
        message.sha256().sha256()
    }
    
    static func ecdsaSign32(msg32: Data, secKey: Data) -> Data {
        let msgCount = 32
        precondition(msg32.count == msgCount)
        
        let keyCount = 32
        precondition(secKey.count == keyCount)
        
        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN))!
        defer { secp256k1_context_destroy(context) }

        var signature = secp256k1_ecdsa_signature()
        let result = msg32.withUnsafeByteBuffer { msg32 in
            secKey.withUnsafeByteBuffer { seckey in
                secp256k1_ecdsa_sign(context, &signature, msg32.baseAddress!, seckey.baseAddress!, secp256k1_nonce_function_rfc6979, nil)
            }
        }
        precondition(result == 1)

        return serialize(signature: signature)
    }
    
    static func serialize(signature: secp256k1_ecdsa_signature) -> Data {
        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_NONE))!
        defer { secp256k1_context_destroy(context) }
        
        let serialized_count = 64
        var serialized = Data(repeating: 0, count: serialized_count)
        
        serialized.withUnsafeMutableByteBuffer { serialized in
            withUnsafePointer(to: signature) { signature in
                _ = secp256k1_ecdsa_signature_serialize_compact(context, serialized.baseAddress!, signature)
            }
        }
        return serialized
    }
    
    static func ecdsaSignature(from serialized: Data) -> secp256k1_ecdsa_signature? {
        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_NONE))!
        defer { secp256k1_context_destroy(context) }

        var sig = secp256k1_ecdsa_signature()
        let result = serialized.withUnsafeByteBuffer { serialized in
            secp256k1_ecdsa_signature_parse_compact(context, &sig, serialized.baseAddress!)
        }
        
        guard result == 1 else {
            return nil
        }
                
        return sig
    }
    
    static func ecdsaSign(message: Data, secKey: Data) -> Data {
        ecdsaSign32(msg32: doubleSHA256(message: message), secKey: secKey)
    }
    
    static func ecdsaVerify32(msg32: Data, signature: secp256k1_ecdsa_signature, publicKey: secp256k1_pubkey) -> Bool {
        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_VERIFY))!
        defer { secp256k1_context_destroy(context) }

        let result = msg32.withUnsafeByteBuffer { msg32 in
            withUnsafePointer(to: signature) { signature in
                withUnsafePointer(to: publicKey) { publicKey in
                    secp256k1_ecdsa_verify(context, signature, msg32.baseAddress!, publicKey)
                }
            }
        }
        return result == 1
    }
    
    static func ecdsaVerify(message: Data, signature: secp256k1_ecdsa_signature, publicKey: secp256k1_pubkey) -> Bool {
        ecdsaVerify32(msg32: doubleSHA256(message: message), signature: signature, publicKey: publicKey)
    }
}

public extension LibSecP256K1 {
    static func schnorrPublicKey(from serialized: Data) -> secp256k1_xonly_pubkey? {
        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_NONE))!
        defer { secp256k1_context_destroy(context) }
        
        var pubKey = secp256k1_xonly_pubkey()
        let result: Int32 = serialized.withUnsafeByteBuffer { serialized in
            return secp256k1_xonly_pubkey_parse(context, &pubKey, serialized.baseAddress!)
        }
        guard result == 1 else {
            return nil
        }
        return pubKey
    }
    
    static func serialize(key: secp256k1_xonly_pubkey) -> Data {
        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_NONE))!
        defer { secp256k1_context_destroy(context) }
        
        var serialized = Data(repeating: 0, count: 32)
        serialized.withUnsafeMutableByteBuffer { serialized in
            withUnsafePointer(to: key) { key in
                _ = secp256k1_xonly_pubkey_serialize(context, serialized.baseAddress!, key)
            }
        }
        return serialized
    }
    
    static func schnorrPublicKey(from keyPair: secp256k1_keypair) -> secp256k1_xonly_pubkey {
        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_NONE))!
        defer { secp256k1_context_destroy(context) }

        var pubKey = secp256k1_xonly_pubkey()
        withUnsafePointer(to: keyPair) { keyPair in
            _ = secp256k1_keypair_xonly_pub(context, &pubKey, nil, keyPair);
        }
        return pubKey
    }

    static func schnorrSign(
        keyPair: secp256k1_keypair,
        msg: Data
    ) -> Data {
        var rng = SecureRandomNumberGenerator()
        return schnorrSignUsing(keyPair: keyPair, msg: msg, rng: &rng)
    }
    
    static func schnorrSignUsing<T: RandomNumberGenerator>(
        keyPair: secp256k1_keypair,
        msg: Data,
        rng: inout T
    ) -> Data {
        let auxRand = rng.randomData(32)
        return schnorrSignWithAuxRand(keyPair: keyPair, msg: msg, auxRand: auxRand)
    }

    static func schnorrSignWithAuxRand(
        keyPair: secp256k1_keypair,
        msg: Data,
        auxRand: Data
    ) -> Data {
        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN))!
        defer { secp256k1_context_destroy(context) }

        var auxRand = auxRand;
        var keyPair = keyPair;
        let sigCount = 64
        var sig64 = Data(repeating: 0, count: sigCount)
        let msgCount = msg.count

        sig64.withUnsafeMutableByteBuffer { sig64 in
            msg.withUnsafeByteBuffer { msg in
                auxRand.withUnsafeMutableByteBuffer { auxRand in
                    var params = secp256k1_schnorrsig_extraparams(
                        magic: (0xda, 0x6f, 0xb3, 0x8c),
                        noncefp: nil,
                        ndata: auxRand.baseAddress
                    )
                    
                    _ = secp256k1_schnorrsig_sign_custom(
                        context,
                        sig64.baseAddress!,
                        msg.baseAddress!,
                        msgCount,
                        &keyPair,
                        &params
                    )
                }
            }
        }
            
        return sig64
    }

    static func schnorrVerify(
        publicKey: secp256k1_xonly_pubkey,
        signature: Data,
        msg: Data
    ) -> Bool {
        precondition(signature.count == 64)
        
        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_VERIFY))!
        defer { secp256k1_context_destroy(context) }

        let msgCount = msg.count
        
        let result: Int32 = signature.withUnsafeByteBuffer { signature in
            msg.withUnsafeByteBuffer { msg in
                withUnsafePointer(to: publicKey) { publicKey in
                    secp256k1_schnorrsig_verify(context, signature.baseAddress!, msg.baseAddress!, msgCount, publicKey)
                }
            }
        }
        return result == 1
    }
}
