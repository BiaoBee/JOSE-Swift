//
//  RandomBytes.swift
//  JOSE
//
//  Created by Biao Luo on 23/04/2026.
//

import Foundation
import Security

func secureRandomBytes(count: Int) throws -> Data {
    var bytes = Data(count: count)
    let status = bytes.withUnsafeMutableBytes { pointer in
        SecRandomCopyBytes(kSecRandomDefault, count, pointer.baseAddress!)
    }
    guard status == errSecSuccess else { throw JWEError.encryptionFailed }
    return bytes
}
