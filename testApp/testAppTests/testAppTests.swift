//
//  testAppTests.swift
//  testAppTests
//
//  Created by Mikhail Nikanorov on 6/28/21.
//  Copyright © 2021 MyEtherWallet Inc. All rights reserved.
//

import XCTest
import LocalAuthentication
@testable import testApp
@testable import mew_wallet_ios_keychain

class testAppTests: XCTestCase {
  static var keychain: Keychain!
  static var badkeychain: Keychain!
  static var key: SecKey!
  
  override class func setUp() {
    keychain = KeychainImplementation(accessGroup: "group.keychain.testapp")
    badkeychain = KeychainImplementation(accessGroup: "group22.keychain22.testapp22")
    
    let keyBase64 = "MIIEpAIBAAKCAQEA5B7lqLrwVCFNUiCmwMr5Q48iuArOolxb7DAuclGnoZVX0SaJ8mrvCOtd6qY/VeBw227txWEPH7840qX/yGxxqTngdNCuDATqYrrbxFOGV30GZmg6NpZYKShTlsftkhiCsoXW0A7m5MCZUkH2/sNBC8oRHCNDXRlsU5bq/yPaAMt6xlBsUgLt/++INcuw+rx1Rm7LJv0FeukQmlekUOL/DMJXcLXCa05StTbvHPiAHOLej07pThCZoX3XHFpOTQ6379EsjvSZHtNhr67qrtRb8or2rX7wt5NWzXHbhUDlyzEcIBB/7G8ygqWhyZTEIMFiRMWSa3KGYZE3nZe5weC7SQIDAQABAoIBAQCjjxehA+++kmYK5YhKIP3Zl64QAQeo18m8rcsPgkZLj3V4a0Zq/orGfWNIE8zDePnSC1YFuBKM86D9P7IGdOKFsA6kEt9HlNqs0UczG6Pt5KGLGV3rt54cXGKacFyA7HwBHf8oDBc2mnUTymIaxcpEdqwP3aS2Ar1trX5uUrlC6UcZyspBZVYvMlU+uAKL1ZtFxjsv0EzuQQW1HX7b2WPUAoxp/yBC/EBRM9K8WbG9i7NB4FTFHAdTMt/EZLGUESizFgrai6lp3s96Apz5GvncRUI+UVP/7zbUaFYdRMW5lrcR8+PL9NACkL2rnQuLoyLKWZWPPlD3WEE9EzY4bH6FAoGBAPu8hL8goEbWMFDZuox04Ouy6EpXR8BDTq8ut6hmad6wpFgZD15Xu7pYEbbsPntdYODKDDAIJCBsiBgf2emL50BpiQkzMPhxyMsN5Pzry9Ys+AzPkJcQ7g+/Wbto9lCC+JmgxtGQ7JIibo1QH7BTsuK9+k72HnZne6oIfaYKbBZfAoGBAOf7/D2Q7NiNcEgxpZRn06+mnkHMb8PfCKfJf/BFf5WKXSkDBZ3XhWSPnZyQnE3gW3lzJjzUwHS+YDk8A0Xl2piAHa/d5O/8eoijB8wa6UGVDBIXqUnfM3Udfry78rM71FOpbzV3H48G7u4CUJMGwOpEqF0TfgtQr4uf8OurdH9XAoGAbdNhVsE1K7Jmgd97s6uKNUpobYaGlyrGOUd4eM+1gKIwEP9d5RsBm9qwX83RtKCYk3mSt6HVoQ+4kE3VFD8lNMTWNF1REBMUNwJo1K9KzrXvwicMPdv1AInK7ChuzdFWBDBQjT1c+KRs9tnt+U+Ky8F2Ytydjaq4GQZ7SuVhIqECgYBMsS+IovrJ9KhkFZWp5FFFRo4XLqDcXkWcQq87HZ66L03xGwCmV/PPdPMkKWKjFELpebnwbl1Zuv5QrZhfaUfFFsW5uF/RPuS7ezo+rb7jYYTmDlB3DYUTeLbHalMoEeV16xPK1yDlxeMDaFx+3sK0MBKBAsqurvP58txQ7RPMbQKBgQCzRcURopG0DF4VF4+xQJS8FpTcnQsQnO/2MJR35npA2iUb+ffs+0lgEdeWs4W46kvaF1iVEPbr6She+aKROzE9Bs25ZCgGLv97oUxDQo0IPvURX7ucN+xOUU1hw9oQDVdGKl1JZh93fn+bjtMTe+26asGLmM0r9YQX1P8qaw3KOg=="
    
    let keyData = Data(base64Encoded: keyBase64)!
    key = SecKeyCreateWithData(keyData as NSData, [
      kSecAttrKeyType: kSecAttrKeyTypeRSA,
      kSecAttrKeyClass: kSecAttrKeyClassPrivate,
    ] as NSDictionary, nil)!
  }
  
  override func setUp() {
    try? testAppTests.keychain.delete(.key(key: nil, label: "key"))
    try? testAppTests.keychain.delete(.key(key: nil, label: "pub"))
    try? testAppTests.keychain.delete(.key(key: nil, label: "key-change"))
    try? testAppTests.keychain.delete(.key(key: nil, label: "pub-change"))
    try? testAppTests.keychain.delete(.data(data: nil, label: "message", account: nil))
    try? testAppTests.keychain.delete(.data(data: nil, label: "message-change", account: nil))
  }
  
  override func tearDown() {
    try? testAppTests.keychain.delete(.key(key: nil, label: "key"))
    try? testAppTests.keychain.delete(.key(key: nil, label: "pub"))
    try? testAppTests.keychain.delete(.key(key: nil, label: "key-change"))
    try? testAppTests.keychain.delete(.key(key: nil, label: "pub-change"))
    try? testAppTests.keychain.delete(.data(data: nil, label: "message", account: nil))
    try? testAppTests.keychain.delete(.data(data: nil, label: "message-change", account: nil))
  }
  
  func testBadKeychainShouldThrowError() {
    let credential = Data([0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    let laContext = LAContext()
    laContext.setCredential(credential, type: .applicationPassword)
    
    XCTAssertThrowsError(try testAppTests.badkeychain.save(.data(data: Data(), label: "label", account: nil)))
    XCTAssertThrowsError(try testAppTests.badkeychain.update(.data(data: Data(), label: "label", account: nil)))
    XCTAssertThrowsError(try testAppTests.badkeychain.load(.data(data: Data(), label: "label", account: nil), context: nil))
    XCTAssertThrowsError(try testAppTests.badkeychain.delete(.data(data: Data(), label: "label", account: nil)))
    XCTAssertThrowsError(try testAppTests.badkeychain.generate(keys: KeychainKeypair(prv: "prv", pub: "pub"), context: laContext))
    XCTAssertThrowsError(try testAppTests.badkeychain.verifySecureEnclave(context: laContext))
    XCTAssertThrowsError(try testAppTests.badkeychain.encrypt(pub: .key(key: nil, label: "pub"), digest: .data(data: Data(), label: nil, account: nil), context: laContext))
    XCTAssertThrowsError(try testAppTests.badkeychain.decrypt(prv: .key(key: nil, label: "prv"), encrypted: .data(data: Data(), label: nil, account: nil), context: laContext))
    XCTAssertThrowsError(try testAppTests.badkeychain.encryptAndSave(pub: .key(key: nil, label: "pub"), item: .data(data: Data(), label: nil, account: nil), context: laContext))
    XCTAssertThrowsError(try testAppTests.badkeychain.loadAndDecrypt(prv: .key(key: nil, label: "prv"), item: .data(data: Data(), label: nil, account: nil), context: laContext))
    XCTAssertThrowsError(try testAppTests.badkeychain.change(keys: KeychainKeypair(prv: "prv", pub: "pub"), item: .data(data: Data(), label: nil, account: nil), oldContext: laContext, newContext: laContext))
  }

  func testSaveKey() {
    do {
      try testAppTests.keychain.save(.key(key: testAppTests.key, label: "key"))
      let key = try testAppTests.keychain.load(.key(key: nil, label: "key"), context: nil).key
      XCTAssertEqual(testAppTests.key, key)
    } catch {
      XCTFail(error.localizedDescription)
    }
  }
  
  func testDoubleSaveKey() {
    XCTAssertNoThrow(try testAppTests.keychain.save(.key(key: testAppTests.key, label: "key")))
    XCTAssertThrowsError(try testAppTests.keychain.save(.key(key: testAppTests.key, label: "key")))
  }
  
  func testUpdateShouldSave() {
    do {
      let text = "This is test data"
      let data = text.data(using: .utf8)!
      
      try testAppTests.keychain.update(.data(data: data, label: "message", account: nil))
      let loaded = try testAppTests.keychain.load(.data(data: nil, label: "message", account: nil), context: nil)
      let loadedText = String(data: loaded.data!, encoding: .utf8)
      
      XCTAssertEqual(data, loaded.data)
      XCTAssertEqual(text, loadedText)
    } catch {
      XCTFail(error.localizedDescription)
    }
  }
  
  func testUpdateShouldUpdate() {
    do {
      let text = "This is test data"
      let updated = "This is updated data"
      let data = text.data(using: .utf8)!
      let updatedData = updated.data(using: .utf8)!
      
      try testAppTests.keychain.update(.data(data: data, label: "message", account: nil))
      let loaded = try testAppTests.keychain.load(.data(data: nil, label: "message", account: nil), context: nil)
      let loadedText = String(data: loaded.data!, encoding: .utf8)
      
      XCTAssertEqual(data, loaded.data)
      XCTAssertEqual(text, loadedText)
      
      try testAppTests.keychain.update(.data(data: updatedData, label: "message", account: nil))
      let loadedUpdate = try testAppTests.keychain.load(.data(data: nil, label: "message", account: nil), context: nil)
      let loadedTextUpdate = String(data: loadedUpdate.data!, encoding: .utf8)
      
      XCTAssertEqual(updatedData, loadedUpdate.data)
      XCTAssertEqual(updated, loadedTextUpdate)
    } catch {
      XCTFail(error.localizedDescription)
    }
  }
  
  func testUpdateShouldNotUpdateNorSaveKey() {
    XCTAssertThrowsError(try testAppTests.keychain.update(.key(key: testAppTests.key, label: "key")))
  }
  
  func testReset() {
    do {
      try testAppTests.keychain.save(.key(key: testAppTests.key, label: "key"))
      XCTAssertNoThrow(try testAppTests.keychain.load(.key(key: nil, label: "key"), context: nil))
      
      let text = "This is test data"
      let data = text.data(using: .utf8)!
      
      try testAppTests.keychain.update(.data(data: data, label: "message", account: nil))
      let loaded = try testAppTests.keychain.load(.data(data: nil, label: "message", account: nil), context: nil)
      let loadedText = String(data: loaded.data!, encoding: .utf8)
      
      XCTAssertEqual(data, loaded.data)
      XCTAssertEqual(text, loadedText)
      
      testAppTests.keychain.reset()
      
      XCTAssertThrowsError(try testAppTests.keychain.load(.key(key: nil, label: "key"), context: nil))
      XCTAssertThrowsError(try testAppTests.keychain.load(.data(data: nil, label: "message", account: nil), context: nil))
    } catch {
      XCTFail(error.localizedDescription)
    }
  }
  
  func testDeleteKey() {
    do {
      try testAppTests.keychain.save(.key(key: testAppTests.key, label: "key"))
      XCTAssertNoThrow(try testAppTests.keychain.load(.key(key: nil, label: "key"), context: nil))
      try testAppTests.keychain.delete(.key(key: nil, label: "key"))
      XCTAssertThrowsError(try testAppTests.keychain.load(.key(key: nil, label: "key"), context: nil))
    } catch {
      XCTFail(error.localizedDescription)
    }
  }
  
  func testGenerateKey() {
    let credential = Data([0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    let laContext = LAContext()
    laContext.setCredential(credential, type: .applicationPassword)
    do {
      let keys = try testAppTests.keychain.generate(keys: KeychainKeypair(prv: "key", pub: "pub", secureEnclave: true), context: laContext)
      XCTAssertNotNil(keys.prv)
      XCTAssertNotNil(keys.pub)
    } catch {
      XCTFail(error.localizedDescription)
    }
  }
  
  func testGenerateAndSaveKey() {
    let credential = Data([0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    let laContext = LAContext()
    laContext.setCredential(credential, type: .applicationPassword)
    do {
      let keys = try testAppTests.keychain.generate(keys: KeychainKeypair(prv: "key", pub: "pub", secureEnclave: true), context: laContext)
      try testAppTests.keychain.delete(.key(key: nil, label: "key"))
      try testAppTests.keychain.delete(.key(key: nil, label: "pub"))
      try testAppTests.keychain.save(keys.pub)
    } catch {
      XCTFail(error.localizedDescription)
    }
  }
  
  func testGenerateAndDoubleSaveKey() {
    let credential = Data([0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    let laContext = LAContext()
    laContext.setCredential(credential, type: .applicationPassword)
    do {
      try testAppTests.keychain.delete(.key(key: nil, label: "key"))
      let keys = try testAppTests.keychain.generate(keys: KeychainKeypair(prv: "key", pub: "pub", secureEnclave: true), context: laContext)
      let load = try testAppTests.keychain.load(.key(key: nil, label: "key"), context: nil).key
      XCTAssertThrowsError(try testAppTests.keychain.save(keys.pub))
      XCTAssertEqual(load, keys.prv.key)
      XCTAssertNotNil(load)
    } catch {
      XCTFail(error.localizedDescription)
    }
  }
  
  func testGenerateEncryptAndDecrypt() {
    let credential = Data([0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    let laContext = LAContext()
    do {
      try testAppTests.keychain.delete(.key(key: nil, label: "key"))
      try testAppTests.keychain.delete(.key(key: nil, label: "pub"))
      
      laContext.setCredential(credential, type: .applicationPassword)
      _ = try testAppTests.keychain.generate(keys: KeychainKeypair(prv: "key", pub: "pub", secureEnclave: true), context: laContext)
      
      let text = "This is test data"
      let data = text.data(using: .utf8)!
      let encrypted = try testAppTests.keychain.encrypt(pub: .key(key: nil, label: "pub"),
                                                        digest: .data(data: data, label: nil, account: nil),
                                                        context: laContext)
      
      let decrypted = try testAppTests.keychain.decrypt(prv: .key(key: nil, label: "key"),
                                                        encrypted: encrypted,
                                                          context: laContext)
      guard let decryptedData = decrypted.data else {
        XCTFail("Empty data")
        return
      }
      let decryptedText = String(data: decryptedData, encoding: .utf8)
      
      XCTAssertEqual(data, decryptedData)
      XCTAssertEqual(decryptedText, text)

      try testAppTests.keychain.delete(.key(key: nil, label: "key"))
      try testAppTests.keychain.delete(.key(key: nil, label: "pub"))
    } catch {
      XCTFail(error.localizedDescription)
    }
  }
  
  func testDoubleGenerate() {
    let credential = Data([0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    let laContext = LAContext()
    laContext.setCredential(credential, type: .applicationPassword)
    XCTAssertNoThrow(try testAppTests.keychain.generate(keys: KeychainKeypair(prv: "key", pub: "pub", secureEnclave: true), context: laContext))
    XCTAssertThrowsError(try testAppTests.keychain.generate(keys: KeychainKeypair(prv: "key", pub: "pub", secureEnclave: true), context: laContext))
    
    do {
      try testAppTests.keychain.delete(.key(key: nil, label: "key"))
    } catch {
      XCTFail(error.localizedDescription)
    }
  }
  
  func testValidateSecureEnclave() {
    let credential = Data([0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    let laContext = LAContext()
    laContext.setCredential(credential, type: .applicationPassword)
    XCTAssertNoThrow(try testAppTests.keychain.verifySecureEnclave(context: laContext))
  }
  
  func testSaveItem() {
    do {
      let text = "This is test message"
      let data = text.data(using: .utf8)!
      try testAppTests.keychain.delete(.data(data: nil, label: "message", account: nil))
      defer {
        try? testAppTests.keychain.delete(.data(data: nil, label: "message", account: nil))
      }
      
      XCTAssertNoThrow(try testAppTests.keychain.save(.data(data: data, label: "message", account: nil)))
      XCTAssertThrowsError(try testAppTests.keychain.save(.data(data: data, label: "message", account: nil)))
    } catch {
      XCTFail(error.localizedDescription)
    }
  }
  
  func testSaveAndLoadItem() {
    do {
      let text = "This is test message"
      let data = text.data(using: .utf8)!
      try testAppTests.keychain.delete(.data(data: nil, label: "message", account: nil))
      defer {
        try? testAppTests.keychain.delete(.data(data: nil, label: "message", account: nil))
      }
      try testAppTests.keychain.save(.data(data: data, label: "message", account: nil))
      
      guard let loaded = try testAppTests.keychain.load(.data(data: nil, label: "message", account: nil), context: nil).data else {
        XCTFail("item not found")
        return
      }
      let loadedText = String(data: loaded, encoding: .utf8)
      XCTAssertEqual(data, loaded)
      XCTAssertEqual(text, loadedText)
    } catch {
      XCTFail(error.localizedDescription)
    }
  }
  
  func testEncryptAndSaveItem() {
    let credential = Data([0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    let laContext = LAContext()
    laContext.setCredential(credential, type: .applicationPassword)
    
    do {
      try testAppTests.keychain.delete(.key(key: nil, label: "key"))
      try testAppTests.keychain.delete(.key(key: nil, label: "pub"))
      
      laContext.setCredential(credential, type: .applicationPassword)
      _ = try testAppTests.keychain.generate(keys: KeychainKeypair(prv: "key", pub: "pub", secureEnclave: true), context: laContext)
      
      let text = "This is test message"
      let data = text.data(using: .utf8)!
      
      try testAppTests.keychain.encryptAndSave(pub: .key(key: nil, label: "pub"),
                                               item: .data(data: data, label: "message", account: nil),
                                               context: laContext)
      
      let encrypted = try testAppTests.keychain.load(.data(data: nil, label: "message", account: nil), context: nil).data
      
      XCTAssertNotEqual(data, encrypted)
      
      let decrypted = try testAppTests.keychain.loadAndDecrypt(prv: .key(key: nil, label: "key"),
                                                               item: .data(data: nil, label: "message", account: nil),
                                                               context: laContext)
      guard let decryptedData = decrypted.data else {
        XCTFail("Empty data")
        return
      }
      let decryptedText = String(data: decryptedData, encoding: .utf8)
      
      XCTAssertEqual(data, decryptedData)
      XCTAssertEqual(text, decryptedText)
    } catch {
      XCTFail(error.localizedDescription)
    }
  }
  
  func testEncryptAndSaveItemAndRegenerateKeys() {
    let credential = Data([0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    let laContext = LAContext()
    laContext.setCredential(credential, type: .applicationPassword)
    
    do {
      
      laContext.setCredential(credential, type: .applicationPassword)
      _ = try testAppTests.keychain.generate(keys: KeychainKeypair(prv: "key", pub: "pub", secureEnclave: true), context: laContext)
      
      let text = "This is test message"
      let data = text.data(using: .utf8)!
      
      try testAppTests.keychain.encryptAndSave(pub: .key(key: nil, label: "pub"),
                                               item: .data(data: data, label: "message", account: nil),
                                               context: laContext)
      
      let encrypted = try testAppTests.keychain.load(.data(data: nil, label: "message", account: nil), context: nil).data
      
      XCTAssertNotEqual(data, encrypted)
      
      try testAppTests.keychain.delete(.key(key: nil, label: "key"))
      try testAppTests.keychain.delete(.key(key: nil, label: "pub"))
      
      _ = try testAppTests.keychain.generate(keys: KeychainKeypair(prv: "key", pub: "pub", secureEnclave: true), context: laContext)
      
      XCTAssertThrowsError(try testAppTests.keychain.loadAndDecrypt(prv: .key(key: nil, label: "key"),
                                                                    item: .data(data: nil, label: "message",
                                                                                account: nil),
                                                                    context: laContext))
    } catch {
      XCTFail(error.localizedDescription)
    }
  }
  
  func testEncryptAndSaveItemAndReplaceKeys() {
    let credential = Data([0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    let laContext = LAContext()
    laContext.setCredential(credential, type: .applicationPassword)
    
    let newCredential = Data([0x01, 0x01, 0x01, 0x01, 0x01, 0x01])
    let newLaContext = LAContext()
    newLaContext.setCredential(newCredential, type: .applicationPassword)
    
    do {
      _ = try testAppTests.keychain.generate(keys: KeychainKeypair(prv: "key", pub: "pub", secureEnclave: true), context: laContext)
      
      let text = "This is test message"
      let data = text.data(using: .utf8)!
      
      try testAppTests.keychain.encryptAndSave(pub: .key(key: nil, label: "pub"),
                                               item: .data(data: data, label: "message", account: nil),
                                               context: laContext)
      
      try testAppTests.keychain.change(keys: KeychainKeypair(prv: "key", pub: "pub", secureEnclave: true),
                                       item: .data(data: nil, label: "message", account: nil),
                                       oldContext: laContext,
                                       newContext: newLaContext)
      
      let decrypted = try testAppTests.keychain.loadAndDecrypt(prv: .key(key: nil, label: "key"),
                                                               item: .data(data: nil, label: "message", account: nil),
                                                               context: newLaContext)
      guard let decryptedData = decrypted.data else {
        XCTFail("Empty data")
        return
      }
      let decryptedText = String(data: decryptedData, encoding: .utf8)
      
      XCTAssertEqual(data, decryptedData)
      XCTAssertEqual(text, decryptedText)
      
      XCTAssertThrowsError(try testAppTests.keychain.loadAndDecrypt(prv: .key(key: nil, label: "key"),
                                                                    item: .data(data: nil, label: "message", account: nil),
                                                                    context: laContext))
    } catch {
      XCTFail(error.localizedDescription)
    }
  }
  
  func testResave() {
    let credential = Data([0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    let laContext = LAContext()
    laContext.setCredential(credential, type: .applicationPassword)
    
    let newCredential = Data([0x01, 0x01, 0x01, 0x01, 0x01, 0x01])
    let newLaContext = LAContext()
    newLaContext.setCredential(newCredential, type: .applicationPassword)
    
    do {
      _ = try testAppTests.keychain.generate(keys: KeychainKeypair(prv: "key", pub: "pub", secureEnclave: true), context: laContext)
      
      let text = "This is test message"
      let data = text.data(using: .utf8)!
      
      try testAppTests.keychain.encryptAndSave(pub: .key(key: nil, label: "pub"),
                                               item: .data(data: data, label: "message", account: nil),
                                               context: laContext)
      
      let decrypted = try testAppTests.keychain.loadAndDecrypt(prv: .key(key: nil, label: "key"),
                                                               item: .data(data: data, label: "message", account: nil),
                                                               context: laContext)
      
      try testAppTests.keychain.delete(.key(key: nil, label: "key"))
      try testAppTests.keychain.delete(.key(key: nil, label: "pub"))
      try testAppTests.keychain.delete(.data(data: nil, label: "message", account: nil))
      
      _ = try testAppTests.keychain.generate(keys: KeychainKeypair(prv: "key", pub: "pub", secureEnclave: true), context: newLaContext)
      
      try testAppTests.keychain.encryptAndSave(pub: .key(key: nil, label: "pub"),
                                               item: .data(data: data, label: "message", account: nil),
                                               context: newLaContext)
      
      let decrypted2 = try testAppTests.keychain.loadAndDecrypt(prv: .key(key: nil, label: "key"),
                                                                item: .data(data: nil, label: "message", account: nil),
                                                                context: newLaContext)
      
      guard let decryptedData = decrypted.data, let decryptedData2 = decrypted2.data else {
        XCTFail("Empty data")
        return
      }
      
      let decryptedText = String(data: decryptedData, encoding: .utf8)
      let decryptedText2 = String(data: decryptedData2, encoding: .utf8)
      
      XCTAssertEqual(data, decryptedData)
      XCTAssertEqual(text, decryptedText)
      
      XCTAssertEqual(decryptedData, decryptedData2)
      XCTAssertEqual(decryptedText, decryptedText2)
      
      XCTAssertThrowsError(try testAppTests.keychain.loadAndDecrypt(prv: .key(key: nil, label: "key"),
                                                                    item: .data(data: nil, label: "message", account: nil),
                                                                    context: laContext))
    } catch {
      XCTFail(error.localizedDescription)
    }
  }
}
