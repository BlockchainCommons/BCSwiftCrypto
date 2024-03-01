import Foundation

public func makeFakeRandomNumberGenerator() -> some RandomNumberGenerator {
    return Xoroshiro256StarStar(state: (17295166580085024720, 422929670265678780, 5577237070365765850, 7953171132032326923))
}

public struct Xoroshiro256StarStar: SeededRandomNumberGenerator {
    public typealias State = (UInt64, UInt64, UInt64, UInt64)
    public var state: State

    public init(state: State) {
        precondition(state != (0, 0, 0, 0))
        self.state = state
    }

    private static func rotl(_ x: UInt64, _ k: UInt64) -> UInt64 {
        return (x << k) | (x >> (64 &- k))
    }

    public init<Source: RandomNumberGenerator>(from source: inout Source) {
        repeat {
            state = (source.next(), source.next(), source.next(), source.next())
        } while state == (0, 0, 0, 0)
    }

    public mutating func next() -> UInt64 {
        let result = Self.rotl(state.1 &* 5, 7) &* 9

        let t = state.1 << 17
        state.2 ^= state.0
        state.3 ^= state.1
        state.1 ^= state.2
        state.0 ^= state.3
    
        state.2 ^= t
    
        state.3 = Self.rotl(state.3, 45)
    
        return result
    }
}
