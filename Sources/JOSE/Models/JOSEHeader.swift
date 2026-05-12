//
//  JOSEHeader.swift
//  JOSE
//
//  Created by Biao Luo on 08/07/2025.
//

internal import AnyCodable
import Foundation

public enum JOSEHeaderError: LocalizedError, Equatable {
    case customParameterNameCollision(String)
    case duplicateCriticalParameter(String)
    case missingCriticalParameter(String)
    case invalidCriticalParameter(String)

    public var errorDescription: String? {
        switch self {
        case .customParameterNameCollision(let name):
            return "Custom JOSE header parameter '\(name)' collides with a registered parameter name."
        case .duplicateCriticalParameter(let name):
            return "Critical JOSE header parameter '\(name)' appears more than once."
        case .missingCriticalParameter(let name):
            return "Critical JOSE header parameter '\(name)' is not present in the header."
        case .invalidCriticalParameter(let name): return "JOSE header parameter '\(name)' cannot be listed in 'crit'."
        }
    }
}

/// Represents a JOSE header for JWS (RFC 7515) and JWE (RFC 7516).
/// Only parameters defined in these RFCs are included.
public struct JOSEHeader: Codable, Equatable {
    // MARK: -  Common parameters (RFC 7515 §4.1, RFC 7516 §4.1)
    /// Algorithm (alg)
    public var alg: JWA
    /// JSON Web Key Set URL (jku)
    public var jku: String?
    /// JSON Web Key (jwk)
    public var jwk: JWK?
    /// Key ID (kid)
    public var kid: String?
    /// X.509 URL (x5u)
    public var x5u: String?
    /// X.509 Certificate Chain (x5c)
    public var x5c: [String]?
    /// X.509 Certificate SHA-1 Thumbprint (x5t)
    public var x5t: String?
    /// X.509 Certificate SHA-256 Thumbprint (x5t#S256)
    public var x5tS256: String?
    /// Type (typ)
    public var typ: String?
    /// Content Type (cty)
    public var cty: String?
    /// Critical (crit)
    public var crit: [String]?

    // MARK: - JWE-specific parameters (RFC 7516 §4.1)
    /// Encryption Algorithm (enc)
    public var enc: String?
    /// Compression Algorithm (zip)
    public var zip: String?
    /// Ephemeral Public Key (epk)
    public var epk: JWK?
    /// Agreement PartyUInfo (apu)
    public var apu: String?
    /// Agreement PartyVInfo (apv)
    public var apv: String?
    /// Initialization Vector (iv)
    public var iv: String?
    /// Authentication Tag (tag)
    public var tag: String?
    /// PBES2 Salt Input (p2s)
    public var p2s: String?
    /// PBES2 Count (p2c)
    public var p2c: Int?

    /// Custom JOSE header parameters that are not part of the registered set.
    public var customParameters: [String: Any]

    public init(
        alg: JWA,
        jku: String? = nil,
        jwk: JWK? = nil,
        kid: String? = nil,
        x5u: String? = nil,
        x5c: [String]? = nil,
        x5t: String? = nil,
        x5tS256: String? = nil,
        typ: String? = nil,
        cty: String? = nil,
        crit: [String]? = nil,
        enc: String? = nil,
        zip: String? = nil,
        epk: JWK? = nil,
        apu: String? = nil,
        apv: String? = nil,
        iv: String? = nil,
        tag: String? = nil,
        p2s: String? = nil,
        p2c: Int? = nil,
        customParameters: [String: Any] = [:]
    ) throws {
        self.alg = alg
        self.jku = jku
        self.jwk = jwk
        self.kid = kid
        self.x5u = x5u
        self.x5c = x5c
        self.x5t = x5t
        self.x5tS256 = x5tS256
        self.typ = typ
        self.cty = cty
        self.crit = crit
        self.enc = enc
        self.zip = zip
        self.epk = epk
        self.apu = apu
        self.apv = apv
        self.iv = iv
        self.tag = tag
        self.p2s = p2s
        self.p2c = p2c
        self.customParameters = customParameters
        try validate()
    }

    enum CodingKeys: String, CodingKey, CaseIterable {
        case alg, jku, jwk, kid, x5u, x5c, x5t
        case x5tS256 = "x5t#S256"
        case typ, cty, crit, enc, zip, epk, apu, apv, iv, tag, p2s, p2c
    }
}

extension JOSEHeader {
    static let registeredParameterNames = Set(CodingKeys.allCases.map(\.rawValue))

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let dynamicContainer = try decoder.container(keyedBy: StringCodingKey.self)

        alg = try container.decode(JWA.self, forKey: .alg)
        jku = try container.decodeIfPresent(String.self, forKey: .jku)
        jwk = try container.decodeIfPresent(JWK.self, forKey: .jwk)
        kid = try container.decodeIfPresent(String.self, forKey: .kid)
        x5u = try container.decodeIfPresent(String.self, forKey: .x5u)
        x5c = try container.decodeIfPresent([String].self, forKey: .x5c)
        x5t = try container.decodeIfPresent(String.self, forKey: .x5t)
        x5tS256 = try container.decodeIfPresent(String.self, forKey: .x5tS256)
        typ = try container.decodeIfPresent(String.self, forKey: .typ)
        cty = try container.decodeIfPresent(String.self, forKey: .cty)
        crit = try container.decodeIfPresent([String].self, forKey: .crit)
        enc = try container.decodeIfPresent(String.self, forKey: .enc)
        zip = try container.decodeIfPresent(String.self, forKey: .zip)
        epk = try container.decodeIfPresent(JWK.self, forKey: .epk)
        apu = try container.decodeIfPresent(String.self, forKey: .apu)
        apv = try container.decodeIfPresent(String.self, forKey: .apv)
        iv = try container.decodeIfPresent(String.self, forKey: .iv)
        tag = try container.decodeIfPresent(String.self, forKey: .tag)
        p2s = try container.decodeIfPresent(String.self, forKey: .p2s)
        p2c = try container.decodeIfPresent(Int.self, forKey: .p2c)

        let decodedParameters = try dynamicContainer.allKeys.reduce(into: [String: Any]()) { result, key in
            let value = try dynamicContainer.decode(AnyCodable.self, forKey: key)
            result[key.stringValue] = value.value
        }
        customParameters = decodedParameters.filter { key, _ in !Self.registeredParameterNames.contains(key) }

        try validate()
    }

    public func encode(to encoder: any Encoder) throws {
        try validate()

        var container = encoder.container(keyedBy: CodingKeys.self)
        var dynamicContainer = encoder.container(keyedBy: StringCodingKey.self)

        try container.encode(alg, forKey: .alg)
        try container.encodeIfPresent(jku, forKey: .jku)
        try container.encodeIfPresent(jwk, forKey: .jwk)
        try container.encodeIfPresent(kid, forKey: .kid)
        try container.encodeIfPresent(x5u, forKey: .x5u)
        try container.encodeIfPresent(x5c, forKey: .x5c)
        try container.encodeIfPresent(x5t, forKey: .x5t)
        try container.encodeIfPresent(x5tS256, forKey: .x5tS256)
        try container.encodeIfPresent(typ, forKey: .typ)
        try container.encodeIfPresent(cty, forKey: .cty)
        try container.encodeIfPresent(crit, forKey: .crit)
        try container.encodeIfPresent(enc, forKey: .enc)
        try container.encodeIfPresent(zip, forKey: .zip)
        try container.encodeIfPresent(epk, forKey: .epk)
        try container.encodeIfPresent(apu, forKey: .apu)
        try container.encodeIfPresent(apv, forKey: .apv)
        try container.encodeIfPresent(iv, forKey: .iv)
        try container.encodeIfPresent(tag, forKey: .tag)
        try container.encodeIfPresent(p2s, forKey: .p2s)
        try container.encodeIfPresent(p2c, forKey: .p2c)

        for (key, value) in customParameters {
            try dynamicContainer.encode(AnyCodable(value), forKey: StringCodingKey(stringValue: key)!)
        }
    }

    func validateCriticalHeaders(understoodCriticalHeaders: Set<String>) throws {
        for name in crit ?? [] where !understoodCriticalHeaders.contains(name) {
            throw UnsupportedCriticalHeaderError.parameter(name)
        }
    }

    private func validate() throws {
        try validateCustomParameterNames()
        try validateCriticalParameterNames()
    }

    private func validateCustomParameterNames() throws {
        for key in customParameters.keys where Self.registeredParameterNames.contains(key) {
            throw JOSEHeaderError.customParameterNameCollision(key)
        }
    }

    private func validateCriticalParameterNames() throws {
        guard let crit else { return }

        var seen = Set<String>()
        let presentParameters = Set(customParameters.keys)

        for name in crit {
            guard seen.insert(name).inserted else { throw JOSEHeaderError.duplicateCriticalParameter(name) }
            guard !Self.registeredParameterNames.contains(name) else {
                throw JOSEHeaderError.invalidCriticalParameter(name)
            }
            guard presentParameters.contains(name) else { throw JOSEHeaderError.missingCriticalParameter(name) }
        }
    }
}

struct UnsupportedCriticalHeaderError: LocalizedError, Equatable {
    let name: String

    var errorDescription: String? { "Critical JOSE header parameter '\(name)' is not understood." }

    static func parameter(_ name: String) -> Self { Self(name: name) }
}

extension JOSEHeader: CustomStringConvertible, CustomDebugStringConvertible {
    /// Returns a JSON string representation of the claims.
    public var description: String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let jsonPresenation = try? encoder.encode(self) else { return "" }
        return String(data: jsonPresenation, encoding: .utf8) ?? ""
    }

    public var debugDescription: String { description }
}

extension JOSEHeader {
    public static func == (lhs: JOSEHeader, rhs: JOSEHeader) -> Bool {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        return (try? encoder.encode(lhs)) == (try? encoder.encode(rhs))
    }
}

extension JOSEHeader {
    func x509CertificateChain() -> [SecCertificate]? {
        guard let x5c else { return nil }
        return x5c.map { $0.replacingOccurrences(of: "\\s+", with: "", options: .regularExpression) }.compactMap {
            Data(base64Encoded: $0)
        }.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
    }
}
