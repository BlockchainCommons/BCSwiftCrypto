import Foundation

public typealias RandomDataFunc = (Int) -> Data

public extension RandomNumberGenerator {
    mutating func randomData(_ count: Int) -> Data {
        (0..<count).reduce(into: Data()) { data, _ in
            data.append(UInt8.random(in: 0...255, using: &self))
        }
    }
}
