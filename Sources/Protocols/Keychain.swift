//
//  Keychain.swift
//  mew-wallet-ios-keychain
//
//  Created by Mikhail Nikanorov on 6/28/21.
//  Copyright © 2021 MyEtherWallet Inc. All rights reserved.
//

import Foundation
import LocalAuthentication

public protocol Keychain {
  var accessGroup: String? { get }
  // MARK: - Keys
  func save(_ record: KeychainRecord) throws
  func update(_ record: KeychainRecord) throws
  func load(_ record: KeychainRecord, context: LAContext?) throws -> KeychainRecord
  func delete(_ record: KeychainRecord) throws
  
  // MARK: - Secure Enclave
  func generate(keys: KeychainKeypair, context: LAContext) throws -> KeychainKeypair
  func verifySecureEnclave(context: LAContext) throws
  
  // MARK: - Encryption
  func encrypt(pub: KeychainRecord, digest: KeychainRecord, context: LAContext) throws -> KeychainRecord 
  func decrypt(prv: KeychainRecord, encrypted: KeychainRecord, context: LAContext) throws -> KeychainRecord 
  func encryptAndSave(pub: KeychainRecord, item: KeychainRecord, context: LAContext) throws 
  func loadAndDecrypt(prv: KeychainRecord, item: KeychainRecord, context: LAContext) throws -> KeychainRecord 
  
  // MARK: - Extra
  func change(keys: KeychainKeypair, item: KeychainRecord, oldContext: LAContext, newContext: LAContext) throws
  func reset()
}
