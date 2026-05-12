//
//  JWTClaims.swift
//  JOSE
//
//  Created by Biao Luo on 04/07/2025.
//

internal import AnyCodable
import Foundation

/// Represents the set of claims in a JWT payload.
/// Standard claims are defined by the IANA JWT registry.
/// Custom/private claims can be added via the `privateClaims` dictionary.
public struct JWTClaims: Codable {
    /// Issuer - identifies principal that issued the JWT ("iss")
    public var iss: String?
    /// Subject - identifies principal that is the subject of the JWT ("sub")
    public var sub: String?
    /// Audience - identifies recipients that the JWT is intended for ("aud")
    public var aud: String?
    /// JWT ID - unique identifier for the JWT ("jti")
    public var jti: String?

    /// Expiration Time - identifies expiration time on or after which the JWT must not be accepted ("exp")
    public var exp: Date?
    /// Not Before - identifies time before which the JWT must not be accepted ("nbf")
    public var nbf: Date?
    /// Issued At - identifies time at which the JWT was issued ("iat")
    public var iat: Date?
    /// Private claims - custom claims not registered with IANA
    public var privateClaims: [String: Any]

    /// Initializes a new Claims object.
    /// - Parameters correspond to standard and private claims.
    public init(
        iss: String? = nil,
        sub: String? = nil,
        aud: String? = nil,
        jti: String? = nil,
        exp: Date? = nil,
        nbf: Date? = nil,
        iat: Date? = nil,
        privateClaims: [String: Any] = [:]
    ) {
        self.iss = iss
        self.sub = sub
        self.aud = aud
        self.exp = exp
        self.nbf = nbf
        self.iat = iat
        self.jti = jti
        self.privateClaims = privateClaims
    }

    enum CodingKeys: CodingKey, CaseIterable { case iss, sub, aud, jti, exp, nbf, iat }

    /// Encodes the claims to the given encoder, handling both standard and private claims.
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(iss, forKey: .iss)
        try container.encodeIfPresent(sub, forKey: .sub)
        try container.encodeIfPresent(aud, forKey: .aud)
        try container.encodeIfPresent(jti, forKey: .jti)
        try container.encodeIfPresent(NumericDate(date: exp), forKey: .exp)
        try container.encodeIfPresent(NumericDate(date: nbf), forKey: .nbf)
        try container.encodeIfPresent(NumericDate(date: iat), forKey: .iat)

        if !privateClaims.isEmpty {
            var dynamicKeyedContainer = encoder.container(keyedBy: StringCodingKey.self)
            for (key, value) in privateClaims {
                try dynamicKeyedContainer.encodeIfPresent(AnyCodable(value), forKey: StringCodingKey(stringValue: key)!)
            }
        }
    }

    /// Decodes the claims from the given decoder, separating public and private claims.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.iss = try container.decodeIfPresent(String.self, forKey: .iss)
        self.sub = try container.decodeIfPresent(String.self, forKey: .sub)
        self.aud = try container.decodeIfPresent(String.self, forKey: .aud)
        self.jti = try container.decodeIfPresent(String.self, forKey: .jti)
        self.exp = (try container.decodeIfPresent(NumericDate.self, forKey: .exp))?.date
        self.nbf = (try container.decodeIfPresent(NumericDate.self, forKey: .nbf))?.date
        self.iat = (try container.decodeIfPresent(NumericDate.self, forKey: .iat))?.date

        let dynamicKeyedContainer = try decoder.singleValueContainer()
        let privateClaims = try dynamicKeyedContainer.decode([String: AnyCodable].self)
        let publicCodingKeys = Set(CodingKeys.allCases.map { $0.stringValue })
        self.privateClaims = privateClaims.filter { key, _ in !publicCodingKeys.contains(key) }.compactMapValues {
            $0.value
        }
    }
}

extension JWTClaims {
    public typealias Key = String
    public typealias Value = Any

    /// Access a private claim by key.
    public subscript(key: String) -> Any? {
        get {
            guard CodingKeys(stringValue: key) == nil else { return nil }
            return privateClaims[key]
        }
        set {
            guard CodingKeys(stringValue: key) == nil else { return }
            privateClaims[key] = newValue
        }
    }
}

extension JWTClaims: CustomStringConvertible, CustomDebugStringConvertible {
    /// Returns a JSON string representation of the claims.
    public var description: String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let jsonPresenation = try? encoder.encode(self) else { return "" }
        return String(data: jsonPresenation, encoding: .utf8) ?? ""
    }

    public var debugDescription: String { description }
}
