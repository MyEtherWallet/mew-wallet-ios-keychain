//
//  LAContext+SecAccessControlCreateFlags.swift
//  mew-wallet-ios-keychain
//
//  Created by Mikhail Nikanorov on 6/28/21.
//  Copyright © 2021 MyEtherWallet Inc. All rights reserved.
//

import Foundation
import LocalAuthentication

extension LAContext {
  var accessControlCreateFlags: SecAccessControlCreateFlags {
    if #available(iOS 11.3, *) {
      return self.isCredentialSet(.applicationPassword) ? [.applicationPassword, .privateKeyUsage] : [.biometryCurrentSet, .privateKeyUsage]
    } else {
      return self.isCredentialSet(.applicationPassword) ? [.applicationPassword, .privateKeyUsage] : [.touchIDCurrentSet, .privateKeyUsage]
    }
  }
}
