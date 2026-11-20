import Foundation

// Reuse Identity's public typed policy/digest parser. Signing is performed
// separately by the one-run fixture owner already pinned during first-HQ.
@main struct ReviewHarnessFixture {
    static func main() throws {
        let args = CommandLine.arguments
        guard args.count == 5, let action = HarnessLaunchAction(rawValue: args[4]) else {
            throw PresenceFailure.invalidChallenge
        }
        let contents = try String(contentsOfFile: args[1], encoding: .utf8)
        try checkHarnessPlan(contents, planID: args[2], digest: args[3], action: action)
    }
}
