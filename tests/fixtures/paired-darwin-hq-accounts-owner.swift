// Hosted CI alone supplies a synthetic P-256 key. The reviewed Identity sources
// authenticate the Machine frame and generate the exact bytes being authorized.
import CryptoKit
import Foundation

@main struct HostedAccountOwner {
    static func main() throws {
        guard ProcessInfo.processInfo.environment["GITHUB_ACTIONS"] == "true",
              ProcessInfo.processInfo.environment["RUNNER_ENVIRONMENT"] == "github-hosted",
              CommandLine.arguments.count == 4 else { throw PresenceFailure.invalidChallenge }
        let args = CommandLine.arguments
        let frame = try Data(contentsOf: URL(fileURLWithPath: args[1]))
        let challenge = try HarnessLaunchChallenge.parse(frame, action: .provision,
            now: Int64(Date().timeIntervalSince1970))
        try HarnessMachinePin.verify(challenge.machine_key,
            published: Data(contentsOf: URL(fileURLWithPath: args[2])))
        let key = try P256.Signing.PrivateKey(rawRepresentation:
            Data(contentsOf: URL(fileURLWithPath: args[3])))
        try challenge.checkOwnerKey(key.publicKey.x963Representation)
        _ = try HarnessNativeReview.text(challenge)
        let signature = try key.signature(for: challenge.signedBytes)
        let proof = ["public_key": key.publicKey.x963Representation.base64EncodedString(),
                     "signature": signature.derRepresentation.base64EncodedString()]
        try FileHandle.standardOutput.write(contentsOf: JSONEncoder().encode(proof))
    }
}
