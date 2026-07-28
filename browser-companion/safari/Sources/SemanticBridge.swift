import CoreFoundation
import Darwin
import Foundation

enum SemanticBridgeError: Error {
  case invalidFrame
  case socketFailure
}

enum SemanticBridge {
  static let socketPath = "/var/run/slipstream-semantic.sock"
  static let maxSignalBytes = 1_024
  static let maxResponseBytes = 1_024
  static let timeoutSeconds: Int = 2

  private static let signalFields: Set<String> = [
    "schema_version",
    "signal_id",
    "source",
    "host",
    "category",
    "confidence_bps",
    "observed_at_unix_ms",
    "top_level",
  ]

  private static let responseFields: Set<String> = [
    "accepted",
    "action",
    "reason",
    "schema_version",
  ]

  static func fixedResponse(
    accepted: Bool,
    action: String,
    reason: String
  ) -> [String: Any] {
    [
      "schema_version": 1,
      "accepted": accepted,
      "action": action,
      "reason": reason,
    ]
  }

  static func validatedSignalData(_ value: Any) -> Data? {
    guard
      let object = value as? [String: Any],
      Set(object.keys) == signalFields,
      let version = integer(object["schema_version"]),
      let category = object["category"] as? String,
      (version == 1 && category == "regional_access_denied")
        || (version == 2 && category == "incomplete_response"),
      let signalID = object["signal_id"] as? String,
      signalID.count == 32,
      signalID.utf8.allSatisfy({
        (48...57).contains($0) || (97...102).contains($0)
      }),
      object["source"] as? String == "browser_extension",
      let host = object["host"] as? String,
      normalizeHostname(host) == host,
      let confidence = integer(object["confidence_bps"]),
      confidence <= 10_000,
      let observedAt = integer(object["observed_at_unix_ms"]),
      observedAt > 0,
      isBoolean(object["top_level"]),
      JSONSerialization.isValidJSONObject(object),
      let data = try? JSONSerialization.data(withJSONObject: object),
      !data.isEmpty,
      data.count <= maxSignalBytes
    else {
      return nil
    }
    return data
  }

  static func validatedDaemonResponse(_ data: Data) -> [String: Any]? {
    guard
      !data.isEmpty,
      data.count <= maxResponseBytes,
      let value = try? JSONSerialization.jsonObject(with: data),
      let object = value as? [String: Any],
      Set(object.keys) == responseFields,
      integer(object["schema_version"]) == 1,
      isBoolean(object["accepted"]),
      let action = object["action"] as? String,
      isToken(action, maxLength: 64),
      let reason = object["reason"] as? String,
      isToken(reason, maxLength: 96)
    else {
      return nil
    }
    return object
  }

  static func exchangeWithDaemon(
    payload: Data,
    path: String = socketPath
  ) throws -> Data {
    guard let request = framed(payload: payload) else {
      throw SemanticBridgeError.invalidFrame
    }

    let descriptor = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
    guard descriptor >= 0 else {
      throw SemanticBridgeError.socketFailure
    }
    defer { Darwin.close(descriptor) }

    var noSignal: Int32 = 1
    guard
      setsockopt(
        descriptor,
        SOL_SOCKET,
        SO_NOSIGPIPE,
        &noSignal,
        socklen_t(MemoryLayout<Int32>.size)
      ) == 0
    else {
      throw SemanticBridgeError.socketFailure
    }

    var timeout = timeval(tv_sec: timeoutSeconds, tv_usec: 0)
    guard
      setsockopt(
        descriptor,
        SOL_SOCKET,
        SO_RCVTIMEO,
        &timeout,
        socklen_t(MemoryLayout<timeval>.size)
      ) == 0,
      setsockopt(
        descriptor,
        SOL_SOCKET,
        SO_SNDTIMEO,
        &timeout,
        socklen_t(MemoryLayout<timeval>.size)
      ) == 0
    else {
      throw SemanticBridgeError.socketFailure
    }

    try connect(descriptor: descriptor, path: path)
    try writeAll(descriptor: descriptor, data: request)
    let header = try readExact(descriptor: descriptor, count: 4)
    guard let responseLength = responseLength(from: header) else {
      throw SemanticBridgeError.invalidFrame
    }
    return try readExact(descriptor: descriptor, count: responseLength)
  }

  static func framed(payload: Data) -> Data? {
    guard !payload.isEmpty, payload.count <= maxSignalBytes else {
      return nil
    }
    var length = UInt32(payload.count).littleEndian
    var result = Data(bytes: &length, count: MemoryLayout<UInt32>.size)
    result.append(payload)
    return result
  }

  static func responseLength(from header: Data) -> Int? {
    guard header.count == MemoryLayout<UInt32>.size else {
      return nil
    }
    let length = header.withUnsafeBytes {
      $0.loadUnaligned(as: UInt32.self).littleEndian
    }
    guard length > 0, length <= maxResponseBytes else {
      return nil
    }
    return Int(length)
  }

  private static func connect(descriptor: Int32, path: String) throws {
    let pathBytes = Array(path.utf8CString)
    var address = sockaddr_un()
    guard pathBytes.count <= MemoryLayout.size(ofValue: address.sun_path) else {
      throw SemanticBridgeError.socketFailure
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
    let result = withUnsafePointer(to: &address) {
      $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
        Darwin.connect(descriptor, $0, addressLength)
      }
    }
    guard result == 0 else {
      throw SemanticBridgeError.socketFailure
    }
  }

  private static func writeAll(descriptor: Int32, data: Data) throws {
    try data.withUnsafeBytes { bytes in
      guard let base = bytes.baseAddress else {
        throw SemanticBridgeError.invalidFrame
      }
      var offset = 0
      while offset < bytes.count {
        let sent = Darwin.send(
          descriptor,
          base.advanced(by: offset),
          bytes.count - offset,
          0
        )
        if sent < 0, errno == EINTR {
          continue
        }
        guard sent > 0 else {
          throw SemanticBridgeError.socketFailure
        }
        offset += sent
      }
    }
  }

  private static func readExact(descriptor: Int32, count: Int) throws -> Data {
    var result = Data(count: count)
    try result.withUnsafeMutableBytes { bytes in
      guard let base = bytes.baseAddress else {
        throw SemanticBridgeError.invalidFrame
      }
      var offset = 0
      while offset < count {
        let received = Darwin.recv(
          descriptor,
          base.advanced(by: offset),
          count - offset,
          0
        )
        if received < 0, errno == EINTR {
          continue
        }
        guard received > 0 else {
          throw SemanticBridgeError.socketFailure
        }
        offset += received
      }
    }
    return result
  }

  private static func normalizeHostname(_ value: String) -> String? {
    guard value.trimmingCharacters(in: .whitespacesAndNewlines) == value else {
      return nil
    }
    var host = value.lowercased()
    if host.hasSuffix(".") {
      host.removeLast()
    }
    guard
      !host.isEmpty,
      host.utf8.count <= 253,
      host.contains("."),
      !isIPv4Address(host)
    else {
      return nil
    }
    let labels = host.split(separator: ".", omittingEmptySubsequences: false)
    guard
      labels.allSatisfy({ label in
        !label.isEmpty
          && label.utf8.count <= 63
          && !label.hasPrefix("-")
          && !label.hasSuffix("-")
          && label.utf8.allSatisfy({
            (97...122).contains($0)
              || (48...57).contains($0)
              || $0 == 45
          })
      })
    else {
      return nil
    }
    return host
  }

  private static func isIPv4Address(_ value: String) -> Bool {
    var address = in_addr()
    return value.withCString {
      inet_pton(AF_INET, $0, &address) == 1
    }
  }

  private static func integer(_ value: Any?) -> UInt64? {
    guard
      let number = value as? NSNumber,
      !isBoolean(number)
    else {
      return nil
    }
    switch CFNumberGetType(number) {
    case .charType, .shortType, .intType, .longType, .longLongType,
      .sInt8Type, .sInt16Type, .sInt32Type, .sInt64Type,
      .cfIndexType, .nsIntegerType:
      break
    default:
      return nil
    }
    let signed = number.int64Value
    guard signed >= 0 else {
      return nil
    }
    return UInt64(signed)
  }

  private static func isBoolean(_ value: Any?) -> Bool {
    guard let number = value as? NSNumber else {
      return false
    }
    return CFGetTypeID(number) == CFBooleanGetTypeID()
  }

  private static func isToken(_ value: String, maxLength: Int) -> Bool {
    !value.isEmpty
      && value.utf8.count <= maxLength
      && value.utf8.allSatisfy({
        (97...122).contains($0) || $0 == 95
      })
  }
}
