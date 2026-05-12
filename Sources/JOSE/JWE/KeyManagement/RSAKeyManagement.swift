//
//  RSAKeyManagement.swift
//  JOSE
//
//  Created by Biao Luo on 23/04/2026.
//

import Foundation
import Security

enum RSAKeyManagement {
    static func wrap(cek: Data, with publicKey: SecKey, algorithm: JWA) throws -> Data {
        guard let secKeyAlgorithm = algorithm.rsaEncryptionAlgorithm,
            SecKeyIsAlgorithmSupported(publicKey, .encrypt, secKeyAlgorithm)
        else { throw JWEError.unsupportedAlgorithm }

        var error: Unmanaged<CFError>?
        guard let encrypted = SecKeyCreateEncryptedData(publicKey, secKeyAlgorithm, cek as CFData, &error) else {
            _ = error?.takeRetainedValue()
            throw JWEError.encryptionFailed
        }
        return encrypted as Data
    }

    static func unwrap(encryptedKey: Data, with privateKey: SecKey, algorithm: JWA) throws -> Data {
        guard let secKeyAlgorithm = algorithm.rsaEncryptionAlgorithm,
            SecKeyIsAlgorithmSupported(privateKey, .decrypt, secKeyAlgorithm)
        else { throw JWEError.unsupportedAlgorithm }

        var error: Unmanaged<CFError>?
        guard let cek = SecKeyCreateDecryptedData(privateKey, secKeyAlgorithm, encryptedKey as CFData, &error) else {
            _ = error?.takeRetainedValue()
            throw JWEError.decryptionFailed
        }
        return cek as Data
    }
}
