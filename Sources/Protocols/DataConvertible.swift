//
//  DataConvertible.swift
//  mew-wallet-ios-keychain
//
//  Created by Mikhail Nikanorov on 6/10/22.
//  Copyright © 2022 MyEtherWallet Inc. All rights reserved.
//


import Foundation

// MARK: - Protocols

public protocol DataConvertible {
  var _data: Data? { get }
}

public protocol ValueConvertible {
  func _value<T>() -> T?
}

// MARK: - Types + DataConvertible

extension Data: DataConvertible {
  public var _data: Data? { self }
}

extension String: DataConvertible {
  public var _data: Data? { self.data(using: .utf8) }
}

extension Bool: DataConvertible {
  public var _data: Data? { Data(from: self) }
}

// MARK: - Data + ValueConvertible

extension Data: ValueConvertible {
  public func _value<T>() -> T? {
    switch T.self {
    case is Data.Type:
      return self as? T
    case is String.Type:
      return String(data: self, encoding: .utf8) as? T
    case is Bool.Type:
      return self.to(type: Bool.self) as? T
    default:
      return nil
    }
  }
}

// MARK: - Data + IntegerLiteral/BooleanLiteral

private extension Data {
  init<T>(from value: T) {
    self = Swift.withUnsafeBytes(of: value) { Data($0) }
  }
  
  func to<T>(type: T.Type) -> T? where T: ExpressibleByIntegerLiteral {
    var value: T = 0
    guard count >= MemoryLayout.size(ofValue: value) else { return nil }
    _ = Swift.withUnsafeMutableBytes(of: &value, { copyBytes(to: $0)} )
    return value
  }
  
  func to<T>(type: T.Type) -> T? where T: ExpressibleByBooleanLiteral {
    var value: T = false
    guard count >= MemoryLayout.size(ofValue: value) else { return nil }
    _ = Swift.withUnsafeMutableBytes(of: &value, { copyBytes(to: $0)} )
    return value
  }
}
