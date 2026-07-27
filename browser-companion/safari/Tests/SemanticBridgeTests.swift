import Darwin
import Dispatch
import Foundation
import XCTest

@testable import SlipstreamSafariBridge

private enum TestSocketError: Error {
  case failed
}

private func validSignal() -> [String: Any] {
  [
    "schema_version": 1,
    "signal_id": "0123456789abcdef0123456789abcdef",
    "source": "browser_extension",
    "host": "weather.com",
    "category": "regional_access_denied",
    "confidence_bps": 9_500,
    "observed_at_unix_ms": 1_000_000,
    "top_level": true,
  ]
}

final class SemanticBridgeTests: XCTestCase {
  func testAcceptsExactSemanticSignal() throws {
    let data = try XCTUnwrap(
      SemanticBridge.validatedSignalData(validSignal())
    )
    let value = try JSONSerialization.jsonObject(with: data)
    let object = try XCTUnwrap(value as? [String: Any])
    XCTAssertEqual(object["host"] as? String, "weather.com")
  }

  func testRejectsExpandedOrMalformedSignal() {
    var expanded = validSignal()
    expanded["url"] = "https://weather.com/private"
    XCTAssertNil(SemanticBridge.validatedSignalData(expanded))

    var address = validSignal()
    address["host"] = "203.0.113.10"
    XCTAssertNil(SemanticBridge.validatedSignalData(address))

    var nonCanonicalHost = validSignal()
    nonCanonicalHost["host"] = "Weather.COM."
    XCTAssertNil(SemanticBridge.validatedSignalData(nonCanonicalHost))

    var badID = validSignal()
    badID["signal_id"] = "NOT-A-SIGNAL-ID"
    XCTAssertNil(SemanticBridge.validatedSignalData(badID))
  }

  func testNativeFrameIsLittleEndianAndBounded() throws {
    let payload = Data([0x41, 0x42, 0x43])
    let frame = try XCTUnwrap(SemanticBridge.framed(payload: payload))
    XCTAssertEqual(Array(frame.prefix(4)), [3, 0, 0, 0])
    XCTAssertEqual(frame.dropFirst(4), payload)

    XCTAssertEqual(
      SemanticBridge.responseLength(from: Data([4, 0, 0, 0])),
      4
    )
    XCTAssertNil(
      SemanticBridge.responseLength(from: Data([0, 0, 0, 0]))
    )
    XCTAssertNil(
      SemanticBridge.responseLength(from: Data([1, 4, 0, 0]))
    )
  }

  func testDaemonResponseCannotExpandBrowserVisibleData() throws {
    let valid = try JSONSerialization.data(withJSONObject: [
      "schema_version": 1,
      "accepted": true,
      "action": "confirm_exact_host_geo_exit",
      "reason": "confirmation_scheduled",
    ])
    XCTAssertNotNil(SemanticBridge.validatedDaemonResponse(valid))

    let expanded = try JSONSerialization.data(withJSONObject: [
      "schema_version": 1,
      "accepted": true,
      "action": "confirm_exact_host_geo_exit",
      "reason": "confirmation_scheduled",
      "host": "weather.com",
    ])
    XCTAssertNil(SemanticBridge.validatedDaemonResponse(expanded))
  }

  func testExchangesOneExactFrameWithUnixSocket() throws {
    let suffix = UUID().uuidString.prefix(8)
    let path = "/tmp/slipstream-semantic-\(suffix).sock"
    let server = try openServer(path: path)
    defer {
      Darwin.close(server)
      Darwin.unlink(path)
    }

    let payload = try XCTUnwrap(
      SemanticBridge.validatedSignalData(validSignal())
    )
    let response = try JSONSerialization.data(withJSONObject: [
      "schema_version": 1,
      "accepted": true,
      "action": "confirm_exact_host_geo_exit",
      "reason": "confirmation_scheduled",
    ])
    let completed = DispatchSemaphore(value: 0)

    DispatchQueue.global(qos: .userInitiated).async {
      defer { completed.signal() }
      let client = Darwin.accept(server, nil, nil)
      guard client >= 0 else {
        return
      }
      defer { Darwin.close(client) }
      guard
        let header = try? readExact(client, count: 4),
        let length = SemanticBridge.responseLength(from: header),
        let received = try? readExact(client, count: length),
        received == payload,
        let frame = SemanticBridge.framed(payload: response)
      else {
        return
      }
      try? writeAll(client, data: frame)
    }

    let received = try SemanticBridge.exchangeWithDaemon(
      payload: payload,
      path: path
    )
    XCTAssertNotNil(SemanticBridge.validatedDaemonResponse(received))
    XCTAssertEqual(completed.wait(timeout: .now() + 2), .success)
  }
}

private func openServer(path: String) throws -> Int32 {
  let descriptor = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
  guard descriptor >= 0 else {
    throw TestSocketError.failed
  }

  Darwin.unlink(path)
  let pathBytes = Array(path.utf8CString)
  var address = sockaddr_un()
  guard pathBytes.count <= MemoryLayout.size(ofValue: address.sun_path) else {
    Darwin.close(descriptor)
    throw TestSocketError.failed
  }
  let addressLength = socklen_t(MemoryLayout<sockaddr_un>.size)
  address.sun_len = UInt8(addressLength)
  address.sun_family = sa_family_t(AF_UNIX)
  withUnsafeMutableBytes(of: &address.sun_path) { destination in
    destination.initializeMemory(as: UInt8.self, repeating: 0)
    for (index, byte) in pathBytes.enumerated() {
      destination[index] = UInt8(bitPattern: byte)
    }
  }

  let bound = withUnsafePointer(to: &address) {
    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
      Darwin.bind(descriptor, $0, addressLength)
    }
  }
  guard
    bound == 0,
    Darwin.chmod(path, S_IRUSR | S_IWUSR) == 0,
    Darwin.listen(descriptor, 1) == 0
  else {
    Darwin.close(descriptor)
    Darwin.unlink(path)
    throw TestSocketError.failed
  }
  return descriptor
}

private func readExact(_ descriptor: Int32, count: Int) throws -> Data {
  var result = Data(count: count)
  try result.withUnsafeMutableBytes { bytes in
    guard let base = bytes.baseAddress else {
      throw TestSocketError.failed
    }
    var offset = 0
    while offset < count {
      let received = Darwin.recv(
        descriptor,
        base.advanced(by: offset),
        count - offset,
        0
      )
      guard received > 0 else {
        throw TestSocketError.failed
      }
      offset += received
    }
  }
  return result
}

private func writeAll(_ descriptor: Int32, data: Data) throws {
  try data.withUnsafeBytes { bytes in
    guard let base = bytes.baseAddress else {
      throw TestSocketError.failed
    }
    var offset = 0
    while offset < bytes.count {
      let sent = Darwin.send(
        descriptor,
        base.advanced(by: offset),
        bytes.count - offset,
        0
      )
      guard sent > 0 else {
        throw TestSocketError.failed
      }
      offset += sent
    }
  }
}
