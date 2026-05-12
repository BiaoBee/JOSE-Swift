//
//  JWA.swift
//  JOSE
//
//  Created by Biao Luo on 09/07/2025.
//

import Foundation
import Security

/// Supported JSON Web Algorithms (JWA) for JWS and JWE.
///
/// This enum covers the algorithms supported by the library's JWS and JWE
/// flows.
public enum JWA: String, Codable {
    // MARK: - JWS algorithms
    /// HMAC using SHA-256 (HS256)
    case HS256
    /// HMAC using SHA-384 (HS384)
    case HS384
    /// HMAC using SHA-512 (HS512)
    case HS512
    /// ECDSA using P-256 and SHA-256 (ES256)
    case ES256
    /// ECDSA using P-384 and SHA-384 (ES384)
    case ES384
    /// ECDSA using P-521 curve and SHA-512(ES512)
    case ES512
    /// RSASSA-PKCS1-v1_5 using SHA-256
    case RS256
    /// RSASSA-PKCS1-v1_5 using SHA-384
    case RS384
    /// RSASSA-PKCS1-v1_5 using SHA-512
    case RS512

    // MARK: - JWE algorithms
    case DIR = "dir"
    case RSA_OAEP = "RSA-OAEP"
    case RSA_OAEP_256 = "RSA-OAEP-256"
    /// ECDH-ES
    case ECDH_ES = "ECDH-ES"
    case ECDH_ES_A128KW = "ECDH-ES+A128KW"
    case ECDH_ES_A256KW = "ECDH-ES+A256KW"

    var secKeyAlgorithm: SecKeyAlgorithm? {
        switch self {
        case .ES256: SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
        case .ES384: SecKeyAlgorithm.ecdsaSignatureMessageX962SHA384
        case .ES512: SecKeyAlgorithm.ecdsaSignatureMessageX962SHA512
        case .RS256: SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA256
        case .RS384: SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA384
        case .RS512: SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA512
        default: nil
        }
    }

    var isSupportedSigningAlgorithm: Bool { isHMACAlgorithm || secKeyAlgorithm != nil }

    var requiresHMACKey: Bool { isHMACAlgorithm }

    var requiresSecKey: Bool { secKeyAlgorithm != nil }

    var isRSAKeyManagementAlgorithm: Bool {
        switch self {
        case .RSA_OAEP, .RSA_OAEP_256: return true
        default: return false
        }
    }

    var isECDHKeyManagementAlgorithm: Bool {
        switch self {
        case .ECDH_ES, .ECDH_ES_A128KW, .ECDH_ES_A256KW: return true
        default: return false
        }
    }

    var ecdhKeyManagementDerivedKeyLengthInBytes: Int? {
        switch self {
        case .ECDH_ES_A128KW: return 16
        case .ECDH_ES_A256KW: return 32
        default: return nil
        }
    }

    var rsaEncryptionAlgorithm: SecKeyAlgorithm? {
        switch self {
        case .RSA_OAEP: return .rsaEncryptionOAEPSHA1
        case .RSA_OAEP_256: return .rsaEncryptionOAEPSHA256
        default: return nil
        }
    }

    var isECDSAAlgorithm: Bool {
        switch self {
        case .ES256, .ES384, .ES512: return true
        default: return false
        }
    }

    var isRSAAlgorithm: Bool {
        switch self {
        case .RS256, .RS384, .RS512: return true
        default: return false
        }
    }

    var isHMACAlgorithm: Bool {
        switch self {
        case .HS256, .HS384, .HS512: return true
        default: return false
        }
    }
}
