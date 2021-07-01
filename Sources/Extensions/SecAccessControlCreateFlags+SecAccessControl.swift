//
//  SecAccessControlCreateFlags+SecAccessControl.swift
//  mew-wallet-ios-keychain
//
//  Created by Mikhail Nikanorov on 6/28/21.
//  Copyright © 2021 MyEtherWallet Inc. All rights reserved.
//

import Foundation

extension SecAccessControlCreateFlags {
  func createAccessControl() throws -> SecAccessControl {
    if self.contains(.privateKeyUsage) {
      let flagsWithOnlyPrivateKeyUsage: SecAccessControlCreateFlags = [.privateKeyUsage]
      guard self != flagsWithOnlyPrivateKeyUsage else {
        throw KeychainError.inconcistency(message: "Couldn't create access control with flags \(self)")
      }
    }
    
    var error: Unmanaged<CFError>?
    let result = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, self, &error)
    guard let accessControl = result else {
      throw KeychainError.fromError(error?.takeRetainedValue(), message: "Tried creating access control object with flags \(self) and protection \(kSecAttrAccessibleWhenUnlockedThisDeviceOnly)")
    }
    return accessControl
  }
}
