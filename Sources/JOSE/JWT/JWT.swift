import Foundation

/// Convenience API for JWTs whose payload is encoded as ``JWTClaims``.
///
/// Use this type when you want to create, parse, validate, encrypt, and decrypt
/// JWTs without working with raw payload bytes directly.
///
/// Supported algorithms:
/// - Signing: `HS256`, `HS384`, `HS512`, `ES256`, `ES384`, `ES512`,
///   `RS256`, `RS384`, `RS512`
/// - Encryption: direct (`dir`), RSA key management, and ECDH key management
///
/// Key setup:
/// - Use `SecKey` for RSA/ECDSA signing and RSA/ECDH encryption.
/// - Use `Data` for HMAC signing and direct encryption.
public struct JWT {
    static func encodeClaims(_ claims: JWTClaims) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        return try encoder.encode(claims)
    }

    static func decodeClaims(from data: Data) throws -> JWTClaims {
        try JSONDecoder().decode(JWTClaims.self, from: data)
    }
}
