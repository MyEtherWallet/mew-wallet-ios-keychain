//
//  KeychainQueryFactory.swift
//  mew-wallet-ios-keychain
//
//  Created by Mikhail Nikanorov on 6/28/21.
//  Copyright © 2021 MyEtherWallet Inc. All rights reserved.
//

import Foundation
import LocalAuthentication

final class KeychainQueryFactory {
  static func save(_ record: KeychainRecord, accessGroup: Keychain.AccessGroup?) throws -> KeychainQuery<Void> {
    switch record {
    case let .data(data, label, account):
      guard let data = data?._data else { throw KeychainError.general(message: "Empty data") }
      return .add(item: data, label: label, account: account, accessGroup: accessGroup)
    case let .key(key, label) where key != nil:
      return .add(key: key!, label: label, accessGroup: accessGroup)
    default:
      throw KeychainError.general(message: "Empty data")
    }
  }
  
  static func update(_ record: KeychainRecord, accessGroup: Keychain.AccessGroup?) throws -> KeychainQuery<Void> {
    switch record {
    case let .data(data, label, account):
      guard let data = data?._data else { throw KeychainError.general(message: "Empty data") }
      return .update(item: data, label: label, account: account, accessGroup: accessGroup)
    case let .key(key, label) where key != nil:
      return .update(key: key!, label: label, accessGroup: accessGroup)
    default:
      throw KeychainError.general(message: "Empty data")
    }
  }
  
  static func delete(_ record: KeychainRecord, accessGroup: Keychain.AccessGroup?) -> KeychainQuery<Void> {
    switch record {
    case let .data(_, label, account):
      return .delete(item: label, account: account, accessGroup: accessGroup)
    case let .key(_, label):
      return .delete(key: label, accessGroup: accessGroup)
    }
  }
  
  static func load<R>(_ record: KeychainRecord, accessGroup: Keychain.AccessGroup?, context: LAContext?) -> KeychainQuery<R> {
    switch record {
    case let .key(_, label):
      return .load(key: label, accessGroup: accessGroup, context: context)
    case let .data(_, label, account):
      return .load(item: label, account: account, accessGroup: accessGroup)
    }
  }
  
  static func generate(_ keys: KeychainKeypair, accessGroup: Keychain.AccessGroup?, context: LAContext?) throws -> KeychainQuery<(prv: SecKey, pub: SecKey)> {
    return try .generate(prvLabel: keys.prv.label,
                         pubLabel: keys.pub.label,
                         accessGroup: accessGroup,
                         context: context,
                         secureEnclave: keys.secureEnclave)
  }
  
  static func deleteAll(_ record: KeychainRecord, accessGroup: Keychain.AccessGroup?) -> KeychainQuery<Void> {
    switch record {
    case .data:
      return .deleteAll(keys: false, accessGroup: accessGroup)
    case .key:
      return .deleteAll(keys: true, accessGroup: accessGroup)
    }
  }
  
  static func all(_ record: KeychainRecord, accessGroup: Keychain.AccessGroup?) -> KeychainQuery<[[String: Any]]> {
    switch record {
    case .data:
      return .all(keys: false, accessGroup: accessGroup)
    case .key:
      return .all(keys: true, accessGroup: accessGroup)
    }
  }
}
