//
//  CryptoSigner.swift
//  JOSE
//
//  Created by Biao Luo on 11/07/2025.
//

import CryptoKit
import Foundation
import Security

enum CryptoSignerError: Error, Equatable {
    case unsupportedAlgorithm
    case signatureVerificationFailed
    case signatureCreationFailed(description: String?)
}

struct CryptoSigner {
    static func sign(data: Data, key: SecKey, alg: JWA) throws -> Signature {
        guard alg.requiresSecKey else { throw CryptoSignerError.unsupportedAlgorithm }
        guard let algorithm = alg.secKeyAlgorithm, SecKeyIsAlgorithmSupported(key, .sign, algorithm) else {
            throw CryptoSignerError.unsupportedAlgorithm
        }

        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(key, algorithm, data as CFData, &error) else {
            let description = error?.takeRetainedValue().localizedDescription
            throw CryptoSignerError.signatureCreationFailed(description: description)
        }

        guard let signature = Signature(derPresentation: signature as Data, algorithm: alg) else {
            throw CryptoSignerError.signatureCreationFailed(description: nil)
        }
        return signature
    }

    static func verifySignature(_ signature: Signature, data: Data, key: SecKey, alg: JWA) throws {
        guard alg.requiresSecKey else { throw CryptoSignerError.unsupportedAlgorithm }
        guard let algorithm = alg.secKeyAlgorithm, SecKeyIsAlgorithmSupported(key, .verify, algorithm) else {
            throw CryptoSignerError.unsupportedAlgorithm
        }

        var error: Unmanaged<CFError>?
        guard SecKeyVerifySignature(key, algorithm, data as CFData, signature.derPresentation as CFData, &error) else {
            _ = error?.takeRetainedValue()
            throw CryptoSignerError.signatureVerificationFailed
        }
    }
}
