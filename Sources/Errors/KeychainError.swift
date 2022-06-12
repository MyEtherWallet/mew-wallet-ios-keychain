//
//  KeychainError.swift
//  mew-wallet-ios-keychain
//
//  Created by Mikhail Nikanorov on 6/28/21.
//  Copyright © 2021 MyEtherWallet Inc. All rights reserved.
//

import Foundation
import LocalAuthentication

public enum KeychainError: LocalizedError {
  case underlying(message: String, error: NSError)
  case inconcistency(message: String)
  case authentication(error: LAError)
  case general(message: String)
  case notFound(message: String)
  case duplicateItem(message: String)
  case invalid

  public var errorDescription: String? {
    switch self {
    case let .underlying(message: message, error: error):
      return "\(message) \(error.localizedDescription)"
    case let .authentication(error: error):
      return "Authentication failed. \(error.localizedDescription)"
    case let .inconcistency(message: message):
      return "Inconcistency in setup, configuration or keychain. \(message)"
    case let .general(message: message):
      return "General error: \(message)"
    case let .notFound(message):
      return "Not found: \(message)"
    case let .duplicateItem(message):
      return "Duplicate item: \(message)"
    case .invalid:
      return "Invalid"
    }
  }

  static func fromError(_ error: CFError?, message: String) -> KeychainError {
    let any = error as Any
    if let authenticationError = any as? LAError {
      return .authentication(error: authenticationError)
    }
    if let error = error,
      let domain = CFErrorGetDomain(error) as String? {
      let code = Int(CFErrorGetCode(error))
      var userInfo: [String: Any] = (CFErrorCopyUserInfo(error) as? [String: Any]) ?? [:]
      if userInfo[NSLocalizedRecoverySuggestionErrorKey] == nil {
        userInfo[NSLocalizedRecoverySuggestionErrorKey] = "See https://www.osstatus.com/search/results?platform=all&framework=all&search=\(code)"
      }
      let underlying = NSError(domain: domain, code: code, userInfo: userInfo)
      return .underlying(message: message, error: underlying)
    }
    return .inconcistency(message: "\(message) Unknown error occured.")
  }
}
