import Foundation
import Blake2

public enum BLAKE2b {
    public static let defaultDigestSize = 64
    
    /// Computes the Blake2b digest of the input buffer.
    public static func hash<D1, D2>(_ data: D1, key: D2?, len: Int = defaultDigestSize) -> Data
    where D1: DataProtocol, D2: DataProtocol
    {
        let dataPtr: any DataPtrRepresentable
        if let dataAsDataPtr = data as? (any DataPtrRepresentable) {
            dataPtr = dataAsDataPtr
        } else {
            dataPtr = Data(data)
        }
        if let keyAsDataPtr = key as? (any DataPtrRepresentable) {
            return try! Blake2b.hash(size: len, data: dataPtr, key: keyAsDataPtr)
        } else {
            if key == nil {
                return try! Blake2b.hash(size: len, data: dataPtr, key: nil as Data?)
            } else {
                return try! Blake2b.hash(size: len, data: dataPtr, key: Data(key!))
            }
        }
    }
    
    /// Computes the Blake2b digest of the input buffer.
    public static func hash<D>(_ data: D, len: Int = defaultDigestSize) -> Data
    where D: DataProtocol
    {
        return hash(data, key: nil as Data?, len: len)
    }
}
