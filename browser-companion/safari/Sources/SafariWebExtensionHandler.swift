import Foundation
import SafariServices

final class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling {
  func beginRequest(with context: NSExtensionContext) {
    let request = context.inputItems.first as? NSExtensionItem
    let message = request?.userInfo?[SFExtensionMessageKey]

    let response: [String: Any]
    if let payload = SemanticBridge.validatedSignalData(message as Any) {
      do {
        let daemonResponse = try SemanticBridge.exchangeWithDaemon(
          payload: payload
        )
        response =
          SemanticBridge.validatedDaemonResponse(daemonResponse)
          ?? SemanticBridge.fixedResponse(
            accepted: false,
            action: "none",
            reason: "invalid_daemon_response"
          )
      } catch {
        response = SemanticBridge.fixedResponse(
          accepted: false,
          action: "none",
          reason: "daemon_unavailable"
        )
      }
    } else {
      response = SemanticBridge.fixedResponse(
        accepted: false,
        action: "none",
        reason: "invalid_signal"
      )
    }

    let item = NSExtensionItem()
    item.userInfo = [SFExtensionMessageKey: response]
    context.completeRequest(returningItems: [item])
  }
}
