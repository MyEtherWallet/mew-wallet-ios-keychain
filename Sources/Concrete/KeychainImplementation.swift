//
//  KeychainImplementation.swift
//  mew-wallet-ios-keychain
//
//  Created by Mikhail Nikanorov on 6/28/21.
//  Copyright © 2021 MyEtherWallet Inc. All rights reserved.
//

import Foundation
import LocalAuthentication

public final class KeychainImplementation: Keychain {
  public let accessGroup: Keychain.AccessGroup?
  
  public init(accessGroup: Keychain.AccessGroup?) {
    self.accessGroup = accessGroup
  }
  
  public func save(_ record: KeychainRecord) throws {
    try self.validateNotFound(record: record, context: nil)
    let query = try KeychainQueryFactory.save(record, accessGroup: self.accessGroup)
    
    do {
      try query.execute().get()
    } catch KeychainQueryError.invalidRecord {
      throw KeychainError.general(message: "Couldn't save record. It's possible that the access control you have provided isn't supported on this OS and/or hardware.")
    } catch KeychainQueryError.missingEntitlement {
      throw KeychainError.general(message: "Couldn't save record. Missing entitlement.")
    } catch KeychainQueryError.duplicateItem {
      throw KeychainError.duplicateItem(message: "Couldn't save record. Duplicate item.")
    } catch let KeychainQueryError.other(status: status) {
      throw KeychainError.general(message: "Couldn't save record. OSStatus: \(status). Record: \(record)")
    }
  }
  
  public func update(_ record: KeychainRecord) throws {
    guard case KeychainRecord.data = record else {
      throw KeychainError.general(message: "Couldn't update record. Not supported.")
    }
    do {
      // Try save first
      try self.save(record)
    } catch KeychainError.duplicateItem {
      // Override record
      let query = try KeychainQueryFactory.update(record, accessGroup: self.accessGroup)
      do {
        try query.execute().get()
      } catch KeychainQueryError.invalidRecord {
        throw KeychainError.general(message: "Couldn't update record. It's possible that the access control you have provided isn't supported on this OS and/or hardware.")
      } catch KeychainQueryError.missingEntitlement {
        throw KeychainError.general(message: "Couldn't update record. Missing entitlement.")
      } catch KeychainQueryError.duplicateItem {
        throw KeychainError.duplicateItem(message: "Couldn't update record. Duplicate item.")
      } catch let KeychainQueryError.other(status: status) {
        throw KeychainError.general(message: "Couldn't update record. OSStatus: \(status). Record: \(record)")
      } catch KeychainQueryError.notFound {
        throw KeychainError.notFound(message: "Couldn't get data for record: \(record)")
      } catch {
        throw error
      }
    }
  }
  
  public func load(_ record: KeychainRecord, context: LAContext?) throws -> KeychainRecord {
    do {
      switch record {
      case .key:
        let query: KeychainQuery<SecKey> = KeychainQueryFactory.load(record, accessGroup: self.accessGroup, context: context)
        let key = try query.execute().get()
        guard let updated = record.withUpdated(key: key) else {
          throw KeychainError.general(message: "Internal error")
        }
        return updated
      case .data:
        let query: KeychainQuery<Data> = KeychainQueryFactory.load(record, accessGroup: self.accessGroup, context: context)
        let data = try query.execute().get()
        guard let updated = record.withUpdated(data: data) else {
          throw KeychainError.general(message: "Internal error")
        }
        return updated
      }
    } catch KeychainQueryError.notFound {
      throw KeychainError.notFound(message: "Couldn't get data for record: \(record)")
    } catch let error as KeychainQueryError {
      throw KeychainError.general(message: "Couldn't get data for record: \(record). Status: \(error.status)")
    } catch {
      throw KeychainError.general(message: "Couldn't get data for record: \(record)")
    }
  }
  
  public func delete(_ record: KeychainRecord) throws {
    let query = KeychainQueryFactory.delete(record, accessGroup: self.accessGroup)
    do {
      try query.execute().get()
    } catch KeychainQueryError.invalidRecord {
      throw KeychainError.general(message: "Couldn't delete key. It's possible that the access control you have provided isn't supported on this OS and/or hardware.")
    } catch let error as KeychainQueryError {
      throw KeychainError.general(message: "Couldn't delete key. OSStatus: \(error.status)")
    } catch {
      throw KeychainError.general(message: "Couldn't delete key")
    }
  }
  
  public func generate(keys: KeychainKeypair, context: LAContext) throws -> KeychainKeypair {
    do {
      try self.validateNotFound(record: keys.prv, context: context)
      try self.validateNotFound(record: keys.pub, context: context)
      let query = try KeychainQueryFactory.generate(keys, accessGroup: self.accessGroup, context: context)
      let generatedKeys = try query.execute().get()
      
      guard let updated = keys.withUpdated(keys: generatedKeys) else {
        throw KeychainError.inconcistency(message: "Can't generate keys")
      }
      if !keys.secureEnclave {
        try self.save(updated.prv)
      }
      try self.save(updated.pub)
      return updated
    } catch {
      try? self.delete(keys.prv)
      try? self.delete(keys.pub)
      throw error
    }
  }
  
  public func verifySecureEnclave(context: LAContext) throws {
    let uuid = UUID().uuidString
    guard let keypair = KeychainKeypair(
      prv: .key(key: nil, label: "prv-\(uuid)"),
      pub: .key(key: nil, label: "pub-\(uuid)")
    ) else {
      throw KeychainError.inconcistency(message: "Can't verify keys")
    }
    
    
    try self.delete(keypair.prv)
    try self.delete(keypair.pub)
    
    let range: ClosedRange<UInt8> = 0...255
    let randomData = Data([UInt8.random(in: range),
                           UInt8.random(in: range),
                           UInt8.random(in: range),
                           UInt8.random(in: range)])
    
    _ = try self.generate(keys: keypair, context: context)
    defer {
      try? self.delete(keypair.prv)
      try? self.delete(keypair.pub)
    }
    
    let encrypted = try self.encrypt(pub: keypair.pub,
                                     digest: .data(data: randomData, label: nil, account: nil),
                                     context: context)
    let decrypted = try self.decrypt(prv: keypair.prv,
                                     encrypted: encrypted,
                                     context: context)
    
    guard randomData == decrypted.data else {
      throw KeychainError.inconcistency(message: "Can't verify keys")
    }
  }
  
  // MARK: - Encryption
  
  public func encrypt(pub: KeychainRecord, digest: KeychainRecord, context: LAContext) throws -> KeychainRecord {
    guard let key = try pub.key ?? self.load(pub, context: context).key else {
      throw KeychainError.notFound(message: "Coundn't find a key: \(pub)")
    }
    guard let data = digest.data else {
      throw KeychainError.general(message: "Empty data.")
    }
    
    var error: Unmanaged<CFError>?
    let result = SecKeyCreateEncryptedData(key, .eciesEncryptionCofactorX963SHA256AESGCM, data as CFData, &error)
    guard let encrypted = result as Data? else {
      if let error = error {
        throw KeychainError.fromError(error.takeRetainedValue(), message: "Could not encrypt.")
      } else {
        throw KeychainError.general(message: "Could not encrypt.")
      }
    }
    guard let updated = digest.withUpdated(data: encrypted) else {
      throw KeychainError.general(message: "Internal error")
    }
    return updated
  }
  
  public func decrypt(prv: KeychainRecord, encrypted: KeychainRecord, context: LAContext) throws -> KeychainRecord {
    guard let key = try prv.key ?? self.load(prv, context: context).key else {
      throw KeychainError.notFound(message: "Coundn't find a key: \(prv)")
    }
    
    guard let data = encrypted.data else {
      throw KeychainError.general(message: "Empty data.")
    }
    
    var error: Unmanaged<CFError>?
    let result = SecKeyCreateDecryptedData(key, .eciesEncryptionCofactorX963SHA256AESGCM, data as CFData, &error)
    guard let decrypted = result as Data? else {
      if let error = error {
        throw KeychainError.fromError(error.takeRetainedValue(), message: "Could not decrypt.")
      } else {
        throw KeychainError.general(message: "Could not decrypt.")
      }
    }
    guard let updated = encrypted.withUpdated(data: decrypted) else {
      throw KeychainError.general(message: "Internal error")
    }
    return updated
  }
  
  public func encryptAndSave(pub: KeychainRecord, item: KeychainRecord, context: LAContext) throws {
    try self.validateNotFound(record: item, context: context)
    let encrypted = try self.encrypt(pub: pub, digest: item, context: context)
    try self.save(encrypted)
  }
  
  public func loadAndDecrypt(prv: KeychainRecord, item: KeychainRecord, context: LAContext) throws -> KeychainRecord {
    let encrypted = try self.load(item, context: context)
    return try self.decrypt(prv: prv, encrypted: encrypted, context: context)
  }
  
  public func change(keys: KeychainKeypair, item: KeychainRecord, oldContext: LAContext, newContext: LAContext) throws {
    // Verify SecureEnclave
    try self.verifySecureEnclave(context: newContext)

    // Generate temporary keypair
    var tempKeys = KeychainKeypair(prv: "\(keys.prv.label ?? "<unset>")-change",
                                   pub: "\(keys.pub.label ?? "<unset>")-change",
                                   secureEnclave: true)
    try? self.delete(tempKeys.prv)
    try? self.delete(tempKeys.pub)
    tempKeys = try self.generate(keys: tempKeys, context: newContext)

    // Load and decrypt old data
    let decrypted = try self.loadAndDecrypt(prv: keys.prv,
                                            item: item,
                                            context: oldContext)

    let backupItem: KeychainRecord = .data(data: decrypted.data,
                                           label: "\(decrypted.label ?? "<unset>")-change",
                                           account: "\(decrypted.account ?? "<unset>")-change")
    // Encrypt and save data to have a backup
    try self.encryptAndSave(pub: tempKeys.pub,
                            item: backupItem,
                            context: newContext)

    // Verify backup
    let decryptedBackup = try self.loadAndDecrypt(prv: tempKeys.prv,
                                                  item: .data(data: nil,
                                                              label: backupItem.label,
                                                              account: backupItem.account),
                                                  context: newContext)
    
    guard decrypted.data != nil, decrypted.data == decryptedBackup.data else {
      try? self.delete(tempKeys.prv)
      try? self.delete(tempKeys.pub)
      try? self.delete(backupItem)
      throw KeychainError.inconcistency(message: "Can't verify backup")
    }

    // Delete old keypair and data
    try? self.delete(item)
    try? self.delete(keys.prv)
    try? self.delete(keys.pub)

    // Generate new keypair
    let newKeys = try self.generate(keys: keys, context: newContext)

    // Save data
    try self.encryptAndSave(pub: newKeys.pub,
                            item: decrypted,
                            context: newContext)

    let newDecrypted = try self.loadAndDecrypt(prv: newKeys.prv,
                                               item: .data(data: nil,
                                                           label: item.label,
                                                           account: item.account),
                                               context: newContext)
      
    guard decrypted.data != nil, decrypted.data == newDecrypted.data else {
      throw KeychainError.inconcistency(message: "Something went wrong")
    }
  }
  
  public func reset() {
    let deleteData = KeychainQueryFactory.deleteAll(.data(data: nil, label: nil, account: nil), accessGroup: self.accessGroup)
    let deleteKeys = KeychainQueryFactory.deleteAll(.key(key: nil, label: nil), accessGroup: self.accessGroup)
    
    _ = try? deleteData.execute().get()
    _ = try? deleteKeys.execute().get()
  }
  
  // MARK: - Private
  
  private func validateNotFound(record: KeychainRecord, context: LAContext?) throws {
    let loadQuery: KeychainQuery<Any> = KeychainQueryFactory.load(record, accessGroup: self.accessGroup, context: context)
    do {
      _ = try loadQuery.execute().get()
      switch record {
      case let .data(_, label, account):
        throw KeychainError.duplicateItem(message: "Duplicate item. Label: \(label ?? "<emtpy>"). Account: \(account ?? "<empty>")")
      case let .key(_, label: label):
        throw KeychainError.duplicateItem(message: "Duplicate key. Label: \(label ?? "<empty>")")
      }
    } catch KeychainQueryError.notFound {
    } catch {
      throw error
    }
  }
}
