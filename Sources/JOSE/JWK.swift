//
//  JWK.swift
//  JOSE
//
//  Created by Biao Luo on 09/07/2025.
//

import Foundation

/// Represents a JSON Web Key (JWK) as defined in RFC 7517.
/// https://datatracker.ietf.org/doc/html/rfc7517
/// This struct supports EC and symmetric keys, and includes common parameters.
public struct JWK: Codable {
    /// Public Key Use (use) - identifies the intended use of the public key (RFC 7517 §4.2)
    public enum Use: String, Codable {
        /// Signature
        case sig
        /// Encryption
        case enc
    }
    
    /// Key Type (kty) - identifies the cryptographic algorithm family (RFC 7517 §4.1)
    /// See: https://www.iana.org/assignments/jose/jose.xhtml#web-key-types
    public enum KeyType: String, Codable {
        /// Elliptic Curve
        case EC
        /// Octet Key Pair (e.g., Ed25519, X25519)
        case OKP
    }
    
    /// Curve (crv) - identifies the cryptographic curve used with the key (RFC 7518 §6.2.1.1, §6.3.1.1)
    /// See: https://www.iana.org/assignments/jose/jose.xhtml
    public enum Curve: String, Codable {
        case P256 = "P-256"
        case P384 = "P-384"
        case P521 = "P-521"
        case Ed25519, Ed448, X25519, X448, secp256k1
    }
    
    /// Key Type (kty) - e.g., "EC", "OKP"
    public let kty: KeyType?
    /// Key ID (kid) - optional identifier for the key (RFC 7517 §4.5)
    public let kid: String?
    /// Algorithm (alg) - optional intended algorithm for the key (RFC 7517 §4.4)
    public let alg: JWA?
    /// Public Key Use (use) - e.g., "sig" (signature), "enc" (encryption) (RFC 7517 §4.2)
    public let use: Use?
    
    // EC/OKP parameters
    /// Curve (crv) - identifies the curve for EC/OKP keys (RFC 7518 §6.2.1.1, §6.3.1.1)
    public let crv: Curve?
    /// X coordinate (x) - base64url-encoded (RFC 7518 §6.2.1.2, §6.3.1.2)
    public let x: String?
    /// Y coordinate (y) - base64url-encoded (RFC 7518 §6.2.1.3)
    public let y: String?
    // public let d: String? // Private key parameter, omitted for public JWK
    
    // Symmetric key parameter
    /// Symmetric key value (k) - base64url-encoded (RFC 7518 §6.4.1)
    public let k: String?
    
    /// Initializes a JWK with the given parameters.
    public init(
        kty: KeyType,
        alg: JWA? = nil,
        use: Use? = nil,
        kid: String? = nil,
        crv: Curve? = nil,
        x: String? = nil,
        y: String? = nil,
        k: String? = nil
    ) {
        self.kty = kty
        self.kid = kid
        self.alg = alg
        self.use = use
        self.crv = crv
        self.x = x
        self.y = y
        self.k = k
    }
    
    /// Convenience factory for EC public keys (RFC 7518 §6.2)
    /// - Parameters:
    ///   - crv: Curve
    ///   - x: X coordinate (base64url-encoded)
    ///   - y: Y coordinate (base64url-encoded)
    ///   - kid: Key ID
    ///   - alg: Algorithm
    ///   - use: Intended use
    /// - Returns: JWK instance for EC public key
    public func ec(crv: Curve,
                   x: String,
                   y: String,
                   alg: JWA? = nil,
                   use: Use? = nil,
                   kid: String? = nil,) -> JWK {
        JWK(kty: .EC, alg: alg, use: use, kid: kid, crv: crv, x: x, y: y)
    }
    
    enum CodingKeys: String, CodingKey {
        case kty, kid, alg, use, crv, x, y, k
    }
}
