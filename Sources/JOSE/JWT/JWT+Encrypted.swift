import Foundation
import Security

extension JWT {
    /// A parsed or created encrypted JWT.
    ///
    /// The `token` property contains the compact JWE, while `header` exposes the
    /// decoded protected header. Decrypt the payload when you need the claims.
    public struct Encrypted {
        /// The JWT header.
        public let header: JOSEHeader
        /// The JWT string.
        public let token: String

        let jwe: JWE

        init(jwe: JWE) {
            self.header = jwe.header
            self.token = jwe.compactSerialization
            self.jwe = jwe
        }

        /// Parses an encrypted JWT string.
        ///
        /// Use this initializer when you already have a compact token and want to
        /// inspect its header before decrypting the payload.
        ///
        /// - Parameter token: The encrypted JWT string to parse.
        /// - Throws:
        ///   - ``JWEError/invalidJWE``
        public init(_ token: String) throws {
            self.init(jwe: try JWE(compactSerialization: token))
        }

        /// Decrypts the JWT into raw payload bytes using an asymmetric key.
        ///
        /// Use this overload for RSA and ECDH key management algorithms.
        ///
        /// - Parameter key: The key used to decrypt the payload.
        /// - Parameter understoodCriticalHeaders: Critical header names that the
        ///   caller understands and accepts. Default is `[]`.
        /// - Throws:
        ///   - ``JWEError/unsupportedAlgorithm``
        ///   - ``JWEError/unsupportedCriticalHeader(_:)``
        ///   - ``JWEError/invalidKey``
        ///   - ``JWEError/decryptionFailed``
        ///   - ``JWEError/invalidTag``
        public func decryptData(
            key: SecKey,
            understoodCriticalHeaders: Set<String> = []
        ) throws -> Data {
            try JWE.decrypt(
                compactSerialization: token,
                key: key,
                understoodCriticalHeaders: understoodCriticalHeaders,
            )
        }

        /// Decrypts the JWT into raw payload bytes using direct symmetric encryption.
        ///
        /// Use this overload for `alg = dir`.
        ///
        /// - Parameter key: The content encryption key.
        /// - Parameter understoodCriticalHeaders: Critical header names that the
        ///   caller understands and accepts. Default is `[]`.
        /// - Throws:
        ///   - ``JWEError/unsupportedAlgorithm``
        ///   - ``JWEError/unsupportedCriticalHeader(_:)``
        ///   - ``JWEError/invalidKey``
        ///   - ``JWEError/decryptionFailed``
        ///   - ``JWEError/invalidTag``
        public func decryptData(
            key: Data,
            understoodCriticalHeaders: Set<String> = []
        ) throws -> Data {
            try JWE.decrypt(
                compactSerialization: token,
                key: key,
                understoodCriticalHeaders: understoodCriticalHeaders,
            )
        }

        /// Decrypts the JWT claims using an asymmetric key.
        ///
        /// Use this overload for RSA and ECDH key management algorithms.
        ///
        /// - Throws:
        ///   - Errors thrown by ``decryptData(key:understoodCriticalHeaders:)``
        ///   - `DecodingError` if the decrypted payload is not valid `JWTClaims` JSON
        public func decryptClaims(
            key: SecKey,
            understoodCriticalHeaders: Set<String> = []
        ) throws -> JWTClaims {
            try JWT.decodeClaims(
                from: decryptData(key: key, understoodCriticalHeaders: understoodCriticalHeaders)
            )
        }

        /// Decrypts the JWT claims using direct symmetric encryption.
        ///
        /// Use this overload for `alg = dir`.
        ///
        /// - Throws:
        ///   - Errors thrown by ``decryptData(key:understoodCriticalHeaders:)``
        ///   - `DecodingError` if the decrypted payload is not valid `JWTClaims` JSON
        public func decryptClaims(
            key: Data,
            understoodCriticalHeaders: Set<String> = []
        ) throws -> JWTClaims {
            try JWT.decodeClaims(
                from: decryptData(key: key, understoodCriticalHeaders: understoodCriticalHeaders)
            )
        }

    }

    /// Creates an encrypted JWT using RSA or ECDH key management.
    ///
    /// Use this overload for JWE algorithms backed by `SecKey`, such as
    /// `RSA-OAEP`, `RSA-OAEP-256`, and `ECDH-ES`.
    ///
    /// - Parameters:
    ///   - header: The JOSE header for the JWT.
    ///   - claims: The claims payload to encrypt.
    ///   - key: The asymmetric encryption key.
    /// - Throws:
    ///   - ``JWEError/unsupportedAlgorithm``
    ///   - ``JWEError/invalidKey``
    ///   - ``JWEError/encryptionFailed``
    public static func encrypt(header: JOSEHeader, claims: JWTClaims, key: SecKey) throws -> Encrypted {
        try encrypt(header: header, data: encodeClaims(claims), key: key)
    }

    /// Creates an encrypted JWT using direct symmetric encryption (`alg = dir`).
    ///
    /// - Parameters:
    ///   - header: The JOSE header for the JWT.
    ///   - claims: The claims payload to encrypt.
    ///   - key: The content encryption key.
    /// - Throws:
    ///   - ``JWEError/unsupportedAlgorithm``
    ///   - ``JWEError/invalidKey``
    ///   - ``JWEError/encryptionFailed``
    public static func encrypt(header: JOSEHeader, claims: JWTClaims, key: Data) throws -> Encrypted {
        try encrypt(header: header, data: encodeClaims(claims), key: key)
    }

    /// Creates an encrypted JWT payload using RSA or ECDH key management.
    ///
    /// Use this overload when the payload is already encoded, such as when
    /// encrypting a nested compact JWT.
    ///
    /// - Parameters:
    ///   - header: The JOSE header for the JWT.
    ///   - data: The payload bytes to encrypt.
    ///   - key: The asymmetric encryption key.
    /// - Throws:
    ///   - ``JWEError/unsupportedAlgorithm``
    ///   - ``JWEError/invalidKey``
    ///   - ``JWEError/encryptionFailed``
    public static func encrypt(header: JOSEHeader, data: Data, key: SecKey) throws -> Encrypted {
        let jwe = try JWE.encrypt(plaintext: data, key: key, header: header)
        return Encrypted(jwe: jwe)
    }

    /// Creates an encrypted JWT payload using direct symmetric encryption (`alg = dir`).
    ///
    /// Use this overload when the payload is already encoded, such as when
    /// encrypting a nested compact JWT.
    ///
    /// - Parameters:
    ///   - header: The JOSE header for the JWT.
    ///   - data: The payload bytes to encrypt.
    ///   - key: The content encryption key.
    /// - Throws:
    ///   - ``JWEError/unsupportedAlgorithm``
    ///   - ``JWEError/invalidKey``
    ///   - ``JWEError/encryptionFailed``
    public static func encrypt(header: JOSEHeader, data: Data, key: Data) throws -> Encrypted {
        let jwe = try JWE.encrypt(plaintext: data, key: key, header: header)
        return Encrypted(jwe: jwe)
    }
}

extension JWT.Encrypted: CustomStringConvertible, CustomDebugStringConvertible {
    /// Returns a readable JSON representation of the JWT header.
    public var description: String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let data = try? encoder.encode(header), let str = String(data: data, encoding: .utf8) {
            return str
        }
        return token
    }

    public var debugDescription: String { description }
}
