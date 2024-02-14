import Foundation

extension Data {
    @inlinable func withUnsafeByteBuffer<ResultType>(_ body: (UnsafeBufferPointer<UInt8>) throws -> ResultType) rethrows -> ResultType {
        try withUnsafeBytes { rawBuf in
            try body(rawBuf.bindMemory(to: UInt8.self))
        }
    }

    @inlinable mutating func withUnsafeMutableByteBuffer<ResultType>(_ body: (UnsafeMutableBufferPointer<UInt8>) throws -> ResultType) rethrows -> ResultType {
        try withUnsafeMutableBytes { rawBuf in
            try body(rawBuf.bindMemory(to: UInt8.self))
        }
    }
}

extension Data {
    init<A>(of a: A) {
        let d = Swift.withUnsafeBytes(of: a) {
            Data($0)
        }
        self = d
    }
}

func toData(utf8: String) -> Data {
    utf8.data(using: .utf8)!
}

extension String {
    var utf8Data: Data {
        toData(utf8: self)
    }
}

func toHex(byte: UInt8) -> String {
    String(format: "%02x", byte)
}

func toHex(data: Data) -> String {
    data.reduce(into: "") {
        $0 += toHex(byte: $1)
    }
}

extension Data {
    var hexString: String {
        toHex(data: self)
    }
}
