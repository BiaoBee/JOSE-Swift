//
//  JOSEHeader.swift
//  JOSE
//
//  Created by Biao Luo on 08/07/2025.
//

import Foundation

/// Represents a JOSE header for JWS (RFC 7515) and JWE (RFC 7516).
/// Only parameters defined in these RFCs are included.
public struct JOSEHeader: Codable {
    // MARK: -  Common parameters (RFC 7515 §4.1, RFC 7516 §4.1)
    /// Algorithm (alg)
    public let alg: JWA?
    /// JSON Web Key Set URL (jku)
    public let jku: String?
    /// JSON Web Key (jwk)
    public let jwk: JWK?
    /// Key ID (kid)
    public let kid: String?
    /// X.509 URL (x5u)
    public let x5u: String?
    /// X.509 Certificate Chain (x5c)
    public let x5c: [String]?
    /// X.509 Certificate SHA-1 Thumbprint (x5t)
    public let x5t: String?
    /// X.509 Certificate SHA-256 Thumbprint (x5t#S256)
    public let x5tS256: String?
    /// Type (typ)
    public let typ: String?
    /// Content Type (cty)
    public let cty: String?
    /// Critical (crit)
    public let crit: [String]?
    
    // MARK: - JWE-specific parameters (RFC 7516 §4.1)
    /// Encryption Algorithm (enc)
    public let enc: String?
    /// Compression Algorithm (zip)
    public let zip: String?
    /// Ephemeral Public Key (epk)
    public let epk: [String: Any]?
    /// Agreement PartyUInfo (apu)
    public let apu: String?
    /// Agreement PartyVInfo (apv)
    public let apv: String?
    /// Initialization Vector (iv)
    public let iv: String?
    /// Authentication Tag (tag)
    public let tag: String?
    /// PBES2 Salt Input (p2s)
    public let p2s: String?
    /// PBES2 Count (p2c)
    public let p2c: Int?
    
    // TODO: - add custom parameters
    public init(
        alg: JWA? = nil,
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
        epk: [String: Any]? = nil,
        apu: String? = nil,
        apv: String? = nil,
        iv: String? = nil,
        tag: String? = nil,
        p2s: String? = nil,
        p2c: Int? = nil
    ) {
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
    }
    
    enum CodingKeys: String, CodingKey, CaseIterable {
        case alg, jku, jwk, kid, x5u, x5c, x5t, x5tS256 = "x5t#S256", typ, cty, crit,
             enc, zip, epk, apu, apv, iv, tag, p2s, p2c
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(alg, forKey: .alg)
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
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.alg = try container.decodeIfPresent(String.self, forKey: .alg)
        self.jku = try container.decodeIfPresent(String.self, forKey: .jku)
        self.jwk = try container.decodeIfPresent([String: AnyCodable].self, forKey: .jwk)
        self.kid = try container.decodeIfPresent(String.self, forKey: .kid)
        self.x5u = try container.decodeIfPresent(String.self, forKey: .x5u)
        self.x5c = try container.decodeIfPresent([String].self, forKey: .x5c)
        self.x5t = try container.decodeIfPresent(String.self, forKey: .x5t)
        self.x5tS256 = try container.decodeIfPresent(String.self, forKey: .x5tS256)
        self.typ = try container.decodeIfPresent(String.self, forKey: .typ)
        self.cty = try container.decodeIfPresent(String.self, forKey: .cty)
        self.crit = try container.decodeIfPresent([String].self, forKey: .crit)
        self.enc = try container.decodeIfPresent(String.self, forKey: .enc)
        self.zip = try container.decodeIfPresent(String.self, forKey: .zip)
        self.epk = try container.decodeIfPresent([String: AnyCodable].self, forKey: .epk)
        self.apu = try container.decodeIfPresent(String.self, forKey: .apu)
        self.apv = try container.decodeIfPresent(String.self, forKey: .apv)
        self.iv = try container.decodeIfPresent(String.self, forKey: .iv)
        self.tag = try container.decodeIfPresent(String.self, forKey: .tag)
        self.p2s = try container.decodeIfPresent(String.self, forKey: .p2s)
        self.p2c = try container.decodeIfPresent(Int.self, forKey: .p2c)
    }
}
