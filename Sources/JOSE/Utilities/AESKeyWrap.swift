//
//  AESKeyWrap.swift
//  JOSE
//
//  Created by Biao Luo on 23/04/2026.
//

import CryptoKit
import Foundation

enum AESKeyWrapError: Error, Equatable {
    case invalidKeyLength
    case wrapFailed
    case unwrapFailed
}

enum AESKeyWrap {
    static func wrap(keyToWrap: Data, kek: Data) throws -> Data {
        guard isValidKeyLength(keyToWrap.count), isValidKeyLength(kek.count) else {
            throw AESKeyWrapError.invalidKeyLength
        }

        guard #available(macOS 12.0, *) else { throw AESKeyWrapError.wrapFailed }

        do { return try AES.KeyWrap.wrap(SymmetricKey(data: keyToWrap), using: SymmetricKey(data: kek)) } catch {
            throw AESKeyWrapError.wrapFailed
        }
    }

    static func unwrap(wrappedKey: Data, kek: Data) throws -> Data {
        guard isValidWrappedKeyLength(wrappedKey.count), isValidKeyLength(kek.count) else {
            throw AESKeyWrapError.invalidKeyLength
        }

        guard #available(macOS 12.0, *) else { throw AESKeyWrapError.unwrapFailed }

        do {
            let unwrapped = try AES.KeyWrap.unwrap(wrappedKey, using: SymmetricKey(data: kek))
            return unwrapped.withUnsafeBytes { Data($0) }
        } catch { throw AESKeyWrapError.unwrapFailed }
    }

    private static func isValidKeyLength(_ length: Int) -> Bool { length == 16 || length == 24 || length == 32 }

    private static func isValidWrappedKeyLength(_ length: Int) -> Bool { length >= 24 && length % 8 == 0 }
}
