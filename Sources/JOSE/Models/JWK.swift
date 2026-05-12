//
//  JWK.swift
//  JOSE
//
//  Created by Biao Luo on 09/07/2025.
//

import CryptoKit
import Foundation
import Security

/// Represents a JSON Web Key (JWK) as defined in RFC 7517.
/// https://datatracker.ietf.org/doc/html/rfc7517
/// This struct supports EC, RSA, OKP, and symmetric keys, and includes common parameters.
public struct JWK: Codable, Equatable {
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
        /// RSA
        case RSA
        /// Octet Key Pair (e.g., Ed25519, X25519)
        case OKP
        /// Octet sequence
        case oct
    }

    /// Curve (crv) - identifies the cryptographic curve used with the key (RFC 7518 §6.2.1.1, §6.3.1.1)
    /// See: https://www.iana.org/assignments/jose/jose.xhtml
    public enum Curve: String, Codable, CaseIterable {
        case P256 = "P-256"
        case P384 = "P-384"
        case P521 = "P-521"
        case Ed25519, Ed448, X25519, X448, secp256k1

        var keySize: Int {
            switch self {
            case .P256, .Ed25519, .X25519, .secp256k1: return 256
            case .P384: return 384
            case .X448: return 448
            case .Ed448: return 456
            case .P521: return 521
            }
        }
    }

    /// Key Type (kty) - e.g., "EC", "OKP"
    public let kty: KeyType?
    /// Key ID (kid) - optional identifier for the key (RFC 7517 §4.5)
    public let kid: String?
    /// Algorithm (alg) - optional intended algorithm for the key (RFC 7517 §4.4)
    public let alg: JWA?
    /// Public Key Use (use) - e.g., "sig" (signature), "enc" (encryption) (RFC 7517 §4.2)
    public let use: Use?

    // EC/OKP/RSA parameters
    /// Curve (crv) - identifies the curve for EC/OKP keys (RFC 7518 §6.2.1.1, §6.3.1.1)
    public let crv: Curve?
    /// X coordinate (x) - base64url-encoded (RFC 7518 §6.2.1.2, §6.3.1.2)
    public let x: String?
    /// Y coordinate (y) - base64url-encoded (RFC 7518 §6.2.1.3)
    public let y: String?
    /// Modulus (n) - base64url-encoded (RFC 7518 §6.3.1.1)
    public let n: String?
    /// Exponent (e) - base64url-encoded (RFC 7518 §6.3.1.2)
    public let e: String?
    // Private key parameter, omitted for public JWK
    public let d: String?
    /// First prime factor (p) - base64url-encoded (RFC 7518 §6.3.2.7)
    public let p: String?
    /// Second prime factor (q) - base64url-encoded (RFC 7518 §6.3.2.8)
    public let q: String?
    /// First factor CRT exponent (dp) - base64url-encoded (RFC 7518 §6.3.2.9)
    public let dp: String?
    /// Second factor CRT exponent (dq) - base64url-encoded (RFC 7518 §6.3.2.10)
    public let dq: String?
    /// First CRT coefficient (qi) - base64url-encoded (RFC 7518 §6.3.2.11)
    public let qi: String?

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
        n: String? = nil,
        e: String? = nil,
        d: String? = nil,
        p: String? = nil,
        q: String? = nil,
        dp: String? = nil,
        dq: String? = nil,
        qi: String? = nil,
        k: String? = nil
    ) {
        self.kty = kty
        self.kid = kid
        self.alg = alg
        self.use = use
        self.crv = crv
        self.x = x
        self.y = y
        self.n = n
        self.e = e
        self.d = d
        self.p = p
        self.q = q
        self.dp = dp
        self.dq = dq
        self.qi = qi
        self.k = k
    }

    /// Convenience factory for EC  keys (RFC 7518 §6.2)
    /// - Parameters:
    ///   - crv: Curve
    ///   - x: X coordinate (base64url-encoded)
    ///   - y: Y coordinate (base64url-encoded)
    ///   - d: Private key
    ///   - kid: Key ID
    ///   - alg: Algorithm
    ///   - use: Intended use
    /// - Returns: JWK instance for EC public key
    static public func ec(
        crv: Curve,
        x: String,
        y: String,
        d: String? = nil,
        alg: JWA? = nil,
        use: Use? = nil,
        kid: String? = nil,
    ) -> JWK { JWK(kty: .EC, alg: alg, use: use, kid: kid, crv: crv, x: x, y: y, d: d) }

    /// Convenience factory for RSA keys (RFC 7518 §6.3).
    static public func rsa(
        n: String,
        e: String,
        d: String? = nil,
        p: String? = nil,
        q: String? = nil,
        dp: String? = nil,
        dq: String? = nil,
        qi: String? = nil,
        alg: JWA? = nil,
        use: Use? = nil,
        kid: String? = nil
    ) -> JWK { JWK(kty: .RSA, alg: alg, use: use, kid: kid, n: n, e: e, d: d, p: p, q: q, dp: dp, dq: dq, qi: qi) }

    enum CodingKeys: String, CodingKey { case kty, kid, alg, use, crv, x, y, n, e, k, d, p, q, dp, dq, qi }
}

extension JWK {
    public func privateECKey() -> SecKey? {
        guard kty == .EC, crv == .P256 || crv == .P384 || crv == .P521 else { return nil }

        guard let d, let dData = Data(base64URLEncoded: d) else { return nil }

        let x963Data: Data? =
            switch crv {
            case .P256: try? P256.Signing.PrivateKey(rawRepresentation: dData).x963Representation
            case .P384: try? P384.Signing.PrivateKey(rawRepresentation: dData).x963Representation
            case .P521: try? P521.Signing.PrivateKey(rawRepresentation: dData).x963Representation
            default: nil
            }
        guard let x963Data else { return nil }

        var error: Unmanaged<CFError>?
        let key = SecKeyCreateWithData(
            x963Data as CFData,
            [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPrivate]
                as NSDictionary,
            &error
        )
        if let error = error {
            print("SecKey error: \(error.takeRetainedValue())")
            return nil
        }
        return key
    }

    public func publicECKey() -> SecKey? {
        guard kty == .EC, crv == .P256 || crv == .P384 || crv == .P521 else { return nil }
        guard let x, let xData = Data(base64URLEncoded: x), let y, let yData = Data(base64URLEncoded: y) else {
            return nil
        }

        let keyData = Data([0x04]) + xData + yData
        var error: Unmanaged<CFError>?
        let key = SecKeyCreateWithData(
            keyData as CFData,
            [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPublic]
                as NSDictionary,
            &error
        )
        if let error = error {
            print("SecKey error: \(error.takeRetainedValue())")
            return nil
        }
        return key
    }

    public func privateRSAKey() -> SecKey? {
        guard kty == .RSA, let n, let nData = Data(base64URLEncoded: n), let e, let eData = Data(base64URLEncoded: e),
            let d, let dData = Data(base64URLEncoded: d), let p, let pData = Data(base64URLEncoded: p), let q,
            let qData = Data(base64URLEncoded: q), let dp, let dpData = Data(base64URLEncoded: dp), let dq,
            let dqData = Data(base64URLEncoded: dq), let qi, let qiData = Data(base64URLEncoded: qi)
        else { return nil }

        let keyData = RSAKeyRepresentation.privateKeyData(
            n: nData,
            e: eData,
            d: dData,
            p: pData,
            q: qData,
            dp: dpData,
            dq: dqData,
            qi: qiData
        )
        var error: Unmanaged<CFError>?
        let key = SecKeyCreateWithData(
            keyData as CFData,
            [
                kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPrivate,
                kSecAttrKeySizeInBits: RSAKeyRepresentation.keySizeInBits(from: nData),
            ] as NSDictionary,
            &error
        )
        if let error = error {
            print("SecKey error: \(error.takeRetainedValue())")
            return nil
        }
        return key
    }

    public func publicRSAKey() -> SecKey? {
        guard kty == .RSA, let n, let nData = Data(base64URLEncoded: n), let e, let eData = Data(base64URLEncoded: e)
        else { return nil }

        let keyData = RSAKeyRepresentation.publicKeyData(modulus: nData, exponent: eData)
        var error: Unmanaged<CFError>?
        let key = SecKeyCreateWithData(
            keyData as CFData,
            [
                kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPublic,
                kSecAttrKeySizeInBits: RSAKeyRepresentation.keySizeInBits(from: nData),
            ] as NSDictionary,
            &error
        )
        if let error = error {
            print("SecKey error: \(error.takeRetainedValue())")
            return nil
        }
        return key
    }

    public func symmetricKey() -> Data? {
        guard kty == .oct, let k else { return nil }
        return Data(base64URLEncoded: k)
    }
}

extension JWK {
    public static func ec(publicKey key: SecKey, alg: JWA? = nil, use: Use? = nil, kid: String? = nil) -> JWK? {
        guard let external = SecKeyCopyExternalRepresentation(key, nil) as Data?, external.count >= 3,
            external.first == 0x04
        else { return nil }

        let coordinateLength = (external.count - 1) / 2
        guard coordinateLength > 0 else { return nil }

        let x = Data(external.dropFirst().prefix(coordinateLength)).base64URLEncodedString
        let y = Data(external.dropFirst(1 + coordinateLength)).base64URLEncodedString

        let crv: Curve? =
            switch coordinateLength {
            case 32: .P256
            case 48: .P384
            case 66: .P521
            default: nil
            }
        guard let crv else { return nil }

        return JWK.ec(crv: crv, x: x, y: y, alg: alg, use: use, kid: kid)
    }

    public static func rsa(publicKey key: SecKey, alg: JWA? = nil, use: Use? = nil, kid: String? = nil) -> JWK? {
        guard let external = SecKeyCopyExternalRepresentation(key, nil) as Data?,
            let components = RSAKeyRepresentation.publicComponents(from: external)
        else { return nil }

        return JWK.rsa(
            n: components.n.base64URLEncodedString,
            e: components.e.base64URLEncodedString,
            alg: alg,
            use: use,
            kid: kid
        )
    }

    public static func rsa(privateKey key: SecKey, alg: JWA? = nil, use: Use? = nil, kid: String? = nil) -> JWK? {
        guard let external = SecKeyCopyExternalRepresentation(key, nil) as Data?,
            let components = RSAKeyRepresentation.privateComponents(from: external)
        else { return nil }

        return JWK.rsa(
            n: components.n.base64URLEncodedString,
            e: components.e.base64URLEncodedString,
            d: components.d.base64URLEncodedString,
            p: components.p.base64URLEncodedString,
            q: components.q.base64URLEncodedString,
            dp: components.dp.base64URLEncodedString,
            dq: components.dq.base64URLEncodedString,
            qi: components.qi.base64URLEncodedString,
            alg: alg,
            use: use,
            kid: kid
        )
    }
}
