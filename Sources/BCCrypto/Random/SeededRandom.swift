import Foundation

public protocol SeededRandomNumberGenerator: RandomNumberGenerator {
    associatedtype State
    init(state: State)
    init<Source: RandomNumberGenerator>(from source: inout Source)
}

public extension SeededRandomNumberGenerator {
    init() {
        var source = SystemRandomNumberGenerator()
        self.init(from: &source)
    }
}
