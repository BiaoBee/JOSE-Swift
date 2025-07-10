//
//  JWA.swift
//  JOSE
//
//  Created by Biao Luo on 09/07/2025.
//

import Foundation

/// Supported JSON Web Algorithms (JWA) for JWS/JWE.
/// See RFC 7518 for details.
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

    // MARK: - JWE algorithms
    case DIR
    /// ECDH-ES
    case ECDH_ES
}
