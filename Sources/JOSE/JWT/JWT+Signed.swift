import Foundation
import Security

extension JWT {
    /// A parsed or created signed JWT.
    ///
    /// The `token` property contains the serialized JWT, while `header`
    /// and `payload` expose the decoded metadata and payload. If the payload
    /// is valid claims JSON, `claims` is populated as a convenience.
    public struct Signed {
        /// The JWT header.
        public let header: JOSEHeader
        /// The raw payload bytes.
        public let payload: Data
        /// The decoded JWT claims, if the payload is valid claims JSON.
        public let claims: JWTClaims?
        /// The JWT string.
        public let token: String

        let jws: JWS

        init(claims: JWTClaims?, jws: JWS) {
            self.claims = claims
            self.header = jws.header
            self.payload = jws.payload
            self.token = jws.compactSerialization
            self.jws = jws
        }

        /// Parses a signed JWT string.
        ///
        /// Use this initializer when you already have a compact token and want to
        /// inspect its header and payload.
        ///
        /// - Parameter token: The signed JWT string to parse.
        /// - Throws:
        ///   - ``JWSError/invalidJWS``
        public init(_ token: String) throws {
            self = Self.make(jws: try JWS(compactSerialization: token))
        }

        /// Validates the JWT using a public or private asymmetric key.
        ///
        /// Use this overload for RSA and ECDSA algorithms.
        ///
        /// - Parameter key: The key used to validate the signature.
        /// - Parameter understoodCriticalHeaders: Critical header names that the
        ///   caller understands and accepts. Default is `[]`.
        /// - Throws:
        ///   - ``JWSError/unsupportedAlgorithm``
        ///   - ``JWSError/signatureVerificationFailed``
        ///   - ``JWSError/certChainVerificationFailed``
        public func validate(key: SecKey, understoodCriticalHeaders: Set<String> = []) throws {
            try jws.validate(key: key, understoodCriticalHeaders: understoodCriticalHeaders)
        }

        /// Validates the JWT using HMAC with a shared secret.
        ///
        /// Use this overload for `HS256`, `HS384`, and `HS512`.
        ///
        /// - Parameter key: The shared secret used to validate the signature.
        /// - Parameter understoodCriticalHeaders: Critical header names that the
        ///   caller understands and accepts. Default is `[]`.
        /// - Throws:
        ///   - ``JWSError/unsupportedAlgorithm``
        ///   - ``JWSError/hmacVerificationFailed``
        public func validate(key: Data, understoodCriticalHeaders: Set<String> = []) throws {
            try jws.validate(key: key, understoodCriticalHeaders: understoodCriticalHeaders)
        }

        /// Validates the JWT against a trusted certificate chain.
        ///
        /// Use this when the token includes an X.509 certificate chain in the
        /// header and you want to verify it against trusted root certificates.
        ///
        /// - Parameter trustedCertificates: Trusted root certificates used to
        ///   validate the certificate chain.
        /// - Parameter understoodCriticalHeaders: Critical header names that the
        ///   caller understands and accepts. Default is `[]`.
        /// - Throws:
        ///   - ``JWSError/missingTrustedCert``
        ///   - ``JWSError/missingCertChain``
        ///   - ``JWSError/certChainInvalid``
        ///   - ``JWSError/certChainVerificationFailed``
        public func validate(
            trustedCertificates: [SecCertificate],
            understoodCriticalHeaders: Set<String> = []
        ) throws {
            try jws.validate(
                trustedCertificates: trustedCertificates,
                understoodCriticalHeaders: understoodCriticalHeaders,
            )
        }

        static func make(jws: JWS) -> Self {
            let decodedClaims = try? JWT.decodeClaims(from: jws.payload)
            return Self(claims: decodedClaims, jws: jws)
        }
    }

    /// Creates a signed JWT using an asymmetric key.
    ///
    /// Use this overload for RSA and ECDSA algorithms. Set ``JOSEHeader/alg``
    /// to one of ``JWA/RS256``, ``JWA/RS384``, ``JWA/RS512``, ``JWA/ES256``,
    /// ``JWA/ES384``, or ``JWA/ES512``.
    ///
    /// - Parameters header: The JOSE header for the JWT.
    ///   - header: The JOSE header for the JWT.
    ///   - claims: The claims payload to sign.
    ///   - key: The asymmetric signing key.
    ///
    /// - Throws:
    ///   - ``JWSError/unsupportedAlgorithm``
    ///   - ``JWSError/signatureCreationFailed``
    public static func sign(header: JOSEHeader, claims: JWTClaims, key: SecKey) throws -> Signed {
        try sign(header: header, payload: encodeClaims(claims), key: key)
    }

    /// Creates a signed JWT using HMAC with a shared secret.
    ///
    /// Use this overload for ``JWA/HS256``, ``JWA/HS384``, or ``JWA/HS512``.
    ///
    /// - Parameters:
    ///   - header: The JOSE header for the JWT.
    ///   - claims: The claims payload to sign.
    ///   - key: The shared secret used for HMAC signing.
    ///
    /// - Throws:
    ///   - ``JWSError/unsupportedAlgorithm``
    ///   - ``JWSError/hmacCreationFailed``
    public static func sign(header: JOSEHeader, claims: JWTClaims, key: Data) throws -> Signed {
        try sign(header: header, payload: encodeClaims(claims), key: key)
    }

    /// Creates a signed JWT payload using an asymmetric key.
    ///
    /// Use this overload when the payload is already encoded, such as when
    /// creating a nested JWT from an existing compact token string.
    ///
    /// - Parameters:
    ///   - header: The JOSE header for the JWT.
    ///   - payload: The payload bytes to sign.
    ///   - key: The asymmetric signing key.
    /// - Throws:
    ///   - ``JWSError/unsupportedAlgorithm``
    ///   - ``JWSError/signatureCreationFailed``
    public static func sign(header: JOSEHeader, payload: Data, key: SecKey) throws -> Signed {
        Signed.make(jws: try JWS.sign(header: header, payload: payload, key: key))
    }

    /// Creates a signed JWT payload using HMAC with a shared secret.
    ///
    /// Use this overload when the payload is already encoded, such as when
    /// creating a nested JWT from an existing compact token string.
    ///
    /// - Parameters:
    ///   - header: The JOSE header for the JWT.
    ///   - payload: The payload bytes to sign.
    ///   - key: The shared secret used for HMAC signing.
    /// - Throws:
    ///   - ``JWSError/unsupportedAlgorithm``
    ///   - ``JWSError/hmacCreationFailed``
    public static func sign(header: JOSEHeader, payload: Data, key: Data) throws -> Signed {
        Signed.make(jws: try JWS.hmac(header: header, payload: payload, key: key))
    }
}

extension JWT.Signed: CustomStringConvertible, CustomDebugStringConvertible {
    /// Returns a readable JSON representation of the JWT header and claims.
    public var description: String {
        struct Representation<Value: Codable>: Codable {
            let header: JOSEHeader
            let payload: Value
        }

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let claims,
            let data = try? encoder.encode(Representation(header: self.header, payload: claims)),
            let str = String(data: data, encoding: .utf8)
        { return str }

        let payloadDescription = String(data: payload, encoding: .utf8) ?? payload.base64EncodedString()
        if let data = try? encoder.encode(Representation(header: self.header, payload: payloadDescription)),
            let str = String(data: data, encoding: .utf8)
        { return str }

        return self.token
    }

    /// Returns the decoded claims when the payload is valid claims JSON.
    ///
    /// - Throws:
    ///   - `DecodingError` if the payload is not valid `JWTClaims` JSON
    public func requireClaims() throws -> JWTClaims {
        if let claims { return claims }
        else {
            return try JWT.decodeClaims(from: payload)
        }
    }

    public var debugDescription: String { description }
}
