//
//  JWEError.swift
//  JOSE
//
//  Created by Biao Luo on 23/04/2026.
//

import Foundation

struct JWEError: LocalizedError, Equatable {
    let errorDescription: String?

    init(_ description: String) { self.errorDescription = description }

    static let invalidJWE = JWEError("Invalid JWE format.")
    static let unsupportedAlgorithm = JWEError("Unsupported JWE algorithm.")
    static let unsupportedEncryption = JWEError("Unsupported content encryption algorithm.")
    static let invalidHeader = JWEError("Invalid or incomplete JWE header.")
    static let invalidKey = JWEError("Invalid key for JWE algorithm.")
    static let encryptionFailed = JWEError("Failed to encrypt JWE payload.")
    static let decryptionFailed = JWEError("Failed to decrypt JWE payload.")
    static let invalidTag = JWEError("Authentication tag verification failed.")
    static func unsupportedCriticalHeader(_ name: String) -> JWEError {
        JWEError("Critical JOSE header parameter '\(name)' is not understood.")
    }
}
