//
//  KeychainQuery.swift
//  mew-wallet-ios-keychain
//
//  Created by Mikhail Nikanorov on 6/28/21.
//  Copyright © 2021 MyEtherWallet Inc. All rights reserved.
//

import Foundation
import LocalAuthentication

enum KeychainQueryOperation {
  case add
  case update([String: Any])
  case delete
  case load
  case generate
  case deleteAll
  case all
}

enum KeychainQueryError: Error {
  case invalidRecord
  case missingEntitlement
  case duplicateItem
  case notFound
  case other(status: OSStatus)
  
  init(status: OSStatus) {
    switch status {
    case errSecInvalidRecord:
      self = .invalidRecord
    case errSecMissingEntitlement:
      self = .missingEntitlement
    case errSecDuplicateItem:
      self = .duplicateItem
    case errSecItemNotFound:
      self = .notFound
    default:
      self = .other(status: status)
    }
  }
  
  var status: OSStatus {
    switch self {
    case .invalidRecord:
      return errSecInvalidRecord
    case .missingEntitlement:
      return errSecMissingEntitlement
    case .duplicateItem:
      return errSecDuplicateItem
    case .notFound:
      return errSecItemNotFound
    case let .other(status):
      return status
    }
  }
}

class KeychainQuery<R> {
  let raw: [String: Any]
  let operation: KeychainQueryOperation
  
  private init(raw: [String: Any], operation: KeychainQueryOperation) {
    self.raw = raw
    self.operation = operation
  }
  
  // MARK: - Add
  
  static func add(key: SecKey, label: String?, accessGroup: String?) -> KeychainQuery<R> {
    var query: [String: Any] = [
      kSecClass               as String: kSecClassKey,
      kSecValueRef            as String: key,
      kSecAttrSynchronizable  as String: false
    ]
    if let label = label {
      query[kSecAttrLabel as String] = label
    }
    
    if let accessGroup = accessGroup {
      query[kSecAttrAccessGroup as String] = accessGroup
    }
    
    return KeychainQuery(raw: query, operation: .add)
  }
  
  static func add(item: Data, label: String?, account: String?, accessGroup: String?) -> KeychainQuery<R> {
    var query: [String: Any] = [
      kSecClass               as String: kSecClassGenericPassword,
      kSecValueData           as String: item,
      kSecAttrSynchronizable  as String: false
    ]
    if let label = label {
      query[kSecAttrLabel as String] = label
    }
    if let account = account {
      query[kSecAttrAccount as String] = account
    }
    
    if let accessGroup = accessGroup {
      query[kSecAttrAccessGroup as String] = accessGroup
    }
    
    return KeychainQuery(raw: query, operation: .add)
  }
  
  // MARK: - Add
  
  static func update(key: SecKey, label: String?, accessGroup: String?) -> KeychainQuery<R> {
    var query: [String: Any] = [
      kSecClass               as String: kSecClassKey,
      kSecAttrSynchronizable  as String: false
    ]
    if let label = label {
      query[kSecAttrLabel as String] = label
    }
    if let accessGroup = accessGroup {
      query[kSecAttrAccessGroup as String] = accessGroup
    }
    
    return KeychainQuery(raw: query, operation: .update([kSecValueRef as String: key]))
  }
  
  static func update(item: Data, label: String?, account: String?, accessGroup: String?) -> KeychainQuery<R> {
    var query: [String: Any] = [
      kSecClass               as String: kSecClassGenericPassword,
      kSecAttrSynchronizable  as String: false
    ]
    if let label = label {
      query[kSecAttrLabel as String] = label
    }
    if let account = account {
      query[kSecAttrAccount as String] = account
    }
    if let accessGroup = accessGroup {
      query[kSecAttrAccessGroup as String] = accessGroup
    }
    
    return KeychainQuery(raw: query, operation: .update([kSecValueData as String: item]))
  }
  
  // MARK: - Delete
  
  static func delete(key label: String?, accessGroup: String?) -> KeychainQuery<R> {
    var query: [String: Any] = [
      kSecClass               as String: kSecClassKey,
      kSecAttrSynchronizable  as String: false
    ]
    if let label = label {
      query[kSecAttrLabel as String] = label
    }
    
    if let accessGroup = accessGroup {
      query[kSecAttrAccessGroup as String] = accessGroup
    }
    
    return KeychainQuery(raw: query, operation: .delete)
  }
  
  static func delete(item label: String?, account: String?, accessGroup: String?) -> KeychainQuery<R> {
    var query: [String: Any] = [
      kSecClass               as String: kSecClassGenericPassword,
      kSecAttrSynchronizable  as String: false
    ]
    if let label = label {
      query[kSecAttrLabel as String] = label
    }
    if let account = account {
      query[kSecAttrAccount as String] = account
    }
    
    if let accessGroup = accessGroup {
      query[kSecAttrAccessGroup as String] = accessGroup
    }
    
    return KeychainQuery(raw: query, operation: .delete)
  }
  
  static func deleteAll(keys: Bool, accessGroup: String?) -> KeychainQuery<R> {
    var query: [String: Any] = [
      kSecAttrSynchronizable as String: false
    ]
    if keys {
      query[kSecClass as String] = kSecClassKey
    } else {
      query[kSecClass as String] = kSecClassGenericPassword
    }
    
    if let accessGroup = accessGroup {
      query[kSecAttrAccessGroup as String] = accessGroup
    }
    
    return KeychainQuery(raw: query, operation: .deleteAll)
  }
  
  // MARK: - Load
  
  static func load(key label: String?, accessGroup: String?, context: LAContext?) -> KeychainQuery<R> {
    var query: [String: Any] = [
      kSecClass               as String: kSecClassKey,
      kSecReturnRef           as String: true,
      kSecAttrSynchronizable  as String: false
    ]
    
    if let label = label {
      query[kSecAttrLabel as String] = label
    }
    
    if let accessGroup = accessGroup {
      query[kSecAttrAccessGroup as String] = accessGroup
    }
    
    if let context = context {
      query[kSecUseAuthenticationContext as String] = context
      if !context.isCredentialSet(.applicationPassword) {
        query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUIAllow
      }
    }
    
    return KeychainQuery(raw: query, operation: .load)
  }
  
  static func load(item label: String?, account: String?, accessGroup: String?) -> KeychainQuery<R> {
    var query: [String: Any] = [
      kSecClass               as String: kSecClassGenericPassword,
      kSecReturnData          as String: true,
      kSecMatchLimit          as String: kSecMatchLimitOne,
      kSecAttrSynchronizable  as String: false
    ]
    if let label = label {
      query[kSecAttrLabel as String] = label
    }
    if let account = account {
      query[kSecAttrAccount as String] = account
    }
    
    if let accessGroup = accessGroup {
      query[kSecAttrAccessGroup as String] = accessGroup
    }
    
    return KeychainQuery(raw: query, operation: .load)
  }
  
  // Generate
  
  static func generate(prvLabel: String?, pubLabel: String?, accessGroup: String?, context: LAContext?, secureEnclave: Bool) throws -> KeychainQuery<R> {
    /* ========= private ========= */
    var prvQuery: [String: Any] = [
      kSecAttrIsPermanent     as String: true,
      kSecAttrSynchronizable  as String: false
    ]
    if let label = prvLabel {
      prvQuery[kSecAttrLabel as String] = label
    }
    
    if let context = context {
      prvQuery[kSecUseAuthenticationContext as String] = context
      if !context.isCredentialSet(.applicationPassword) {
        prvQuery[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUIAllow
      }
    }
    
    if let context = context {
      prvQuery[kSecAttrAccessControl as String] = try context.accessControlCreateFlags.createAccessControl()
    } else {
      prvQuery[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    }
    
    /* ========= public ========= */
    var pubQuery: [String: Any] = [
      kSecClass               as String: kSecClassKey,
      kSecAttrAccessible      as String: kSecAttrAccessibleAlwaysThisDeviceOnly,
      kSecAttrSynchronizable  as String: false
    ]
    if let label = pubLabel {
      pubQuery[kSecAttrLabel as String] = label
    }
    
    if let accessGroup = accessGroup {
      prvQuery[kSecAttrAccessGroup as String] = accessGroup
      pubQuery[kSecAttrAccessGroup as String] = accessGroup
    }
     
    /* ========= combined ========= */
    var query: [String: Any] = [
      kSecAttrKeyType         as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecPrivateKeyAttrs     as String: prvQuery,
      kSecPublicKeyAttrs      as String: pubQuery,
      kSecAttrKeySizeInBits   as String: 256,
      kSecAttrSynchronizable  as String: false
    ]
    
    if secureEnclave {
      query[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
    }
    
    return KeychainQuery(raw: query, operation: .generate)
  }
  
  // MARK: - All
  
  static func all(keys: Bool, accessGroup: String?) -> KeychainQuery<R> {
    var query: [String: Any] = [
      kSecReturnData          as String: false,
      kSecReturnAttributes    as String: true,
      kSecMatchLimit          as String: kSecMatchLimitAll,
      kSecAttrSynchronizable  as String: false
    ]
    if keys {
      query[kSecClass as String] = kSecClassKey
    } else {
      query[kSecClass as String] = kSecClassGenericPassword
    }
    
    if let accessGroup = accessGroup {
      query[kSecAttrAccessGroup as String] = accessGroup
    }
    
    return KeychainQuery(raw: query, operation: .all)
  }
  
  // MARK: - Execute
  
  func execute() -> Result<R, KeychainQueryError> {
    let status: OSStatus
    switch self.operation {
    case .add:
      status = SecItemAdd(self.raw as CFDictionary, nil)
      guard status == errSecSuccess else {
        return .failure(KeychainQueryError(status: status))
      }
      return .success(() as! R)
    case let .update(update):
      status = SecItemUpdate(self.raw as CFDictionary, update as CFDictionary)
      guard status == errSecSuccess else {
        return .failure(KeychainQueryError(status: status))
      }
      return .success(() as! R)
    case .delete:
      status = SecItemDelete(self.raw as CFDictionary)
      guard status == errSecSuccess || status == errSecItemNotFound else {
        return .failure(KeychainQueryError(status: status))
      }
      return .success(() as! R)
    case .load:
      var raw: CFTypeRef?
      status = SecItemCopyMatching(self.raw as CFDictionary, &raw)
      guard status == errSecSuccess, raw != nil else {
        if raw == nil {
          return .failure(.notFound)
        } else {
          return .failure(KeychainQueryError(status: status))
        }
      }
      return .success(raw as! R)
    case .generate:
      var publicSecKey: SecKey?
      var privateSecKey: SecKey?
      
      let status = SecKeyGeneratePair(self.raw as CFDictionary, &publicSecKey, &privateSecKey)
      guard status == errSecSuccess, privateSecKey != nil, publicSecKey != nil else {
        return .failure(KeychainQueryError(status: status))
      }
      return .success((privateSecKey, publicSecKey) as! R)
    case .deleteAll:
      status = SecItemDelete(self.raw as CFDictionary)
      guard status == errSecSuccess || status == errSecItemNotFound else {
        return .failure(KeychainQueryError(status: status))
      }
      return .success(() as! R)
    case .all:
      var raw: CFTypeRef?
      status = SecItemCopyMatching(self.raw as CFDictionary, &raw)
      guard status == errSecSuccess, raw != nil else {
        if raw == nil {
          return .failure(.notFound)
        } else {
          return .failure(KeychainQueryError(status: status))
        }
      }
      return .success(raw as! R)
    }
  }
}
