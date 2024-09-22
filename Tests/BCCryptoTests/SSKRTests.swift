import Testing
import BCCrypto
import BCRandom

struct SSKRTests {
    @Test func test1() throws {
        let secret = secureRandomData(32)
        let shares = try splitSSKR(groupThreshold: 1, groups: [(2, 3)], secret: secret).flatMap { $0 }
        let recoveredShares = [shares[0], shares[2]]
        let recoveredSecret = try combineSSKR(shares: recoveredShares)
        #expect(secret == recoveredSecret)
    }
}
