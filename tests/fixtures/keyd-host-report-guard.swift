import Foundation

@main
struct HostReportGuardTest {
    static func allowed(_ purpose: String, _ length: Int, op: Int32 = 2) -> Bool {
        var message = Array("\(purpose)\u{0}".utf8)
        precondition(length >= message.count)
        message += Array(repeating: 0x61, count: length - message.count)
        return message.withUnsafeBufferPointer { bytes in
            keydFixedHostReportMessage(op, bytes.baseAddress!, bytes.count)
        }
    }

    static func main() {
        let v1 = "agent-bot/qualification-host-report/v1"
        let v2 = "agent-bot/qualification-host-report/v2"
        let limit = 1_048_576 + Array("\(v2)\u{0}".utf8).count
        precondition(allowed(v1, 8_383))
        precondition(allowed(v2, 8_383))
        precondition(allowed(v2, limit))
        precondition(!allowed(v2, limit + 1))
        precondition(!allowed(v2, 8_383, op: 1))
        precondition(!allowed("agent-bot/qualification-host-report/v3", 8_383))
        precondition(!allowed("arbitrary-signing-purpose", 8_383))
        print("fixed v1/v2 host-report native signing bounds passed")
    }
}
