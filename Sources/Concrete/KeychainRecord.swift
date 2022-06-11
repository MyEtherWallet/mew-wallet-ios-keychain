//
//  KeychainRecord.swift
//  mew-wallet-ios-keychain
//
//  Created by Mikhail Nikanorov on 6/29/21.
//  Copyright © 2021 MyEtherWallet Inc. All rights reserved.
//

import Foundation

public struct KeychainKeypair {
  public let prv: KeychainRecord
  public let pub: KeychainRecord
  public let secureEnclave: Bool
  
  public init?(prv: KeychainRecord, pub: KeychainRecord, secureEnclave: Bool = true) {
    guard case .key = prv, case .key = pub else {
      return nil
    }
    self.prv = prv
    self.pub = pub
    self.secureEnclave = secureEnclave
  }
  
  public init(prv: KeychainRecord.Label, pub: KeychainRecord.Label, secureEnclave: Bool = true) {
    self.prv = .key(key: nil, label: prv)
    self.pub = .key(key: nil, label: pub)
    self.secureEnclave = secureEnclave
  }
  
  func withUpdated(keys: (prv: SecKey, pub: SecKey)) -> KeychainKeypair? {
    return KeychainKeypair(
      prv: .key(key: keys.prv, label: self.prv.label),
      pub: .key(key: keys.pub, label: self.pub.label),
      secureEnclave: self.secureEnclave
    )
  }
}

public enum KeychainRecord {
  public typealias Label = String
  public typealias Account = String
  case data(data: DataConvertible?, label: Label?, account: Account?)
  case key(key: SecKey?, label: Label?)
  
  public var label: Label? {
    switch self {
    case let .key(_, label):
      return label
    case let .data(_, label, _):
      return label
    }
  }
  
  public var account: Account? {
    switch self {
    case .key:
      return nil
    case let .data(_, _, account):
      return account
    }
  }
  
  public var key: SecKey? {
    guard case let .key(key, _) = self else {
      return nil
    }
    return key
  }
  
  public var data: Data? {
    guard case let .data(data, _, _) = self else {
      return nil
    }
    return data?._data
  }
  
  public func value<T>() -> T? {
    guard case let .data(data, _, _) = self else {
      return nil
    }
    return (data as? ValueConvertible)?._value()
  }
  
  public func withUpdated(data: Data) -> KeychainRecord? {
    guard case let .data(_, label, account) = self else {
      return nil
    }
    return .data(data: data, label: label, account: account)
  }
  
  public func withUpdated(key: SecKey) -> KeychainRecord? {
    guard case let .key(_, label) = self else {
      return nil
    }
    return .key(key: key, label: label)
  }
}
