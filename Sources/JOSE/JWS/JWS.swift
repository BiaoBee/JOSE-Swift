//
//  JWS.swift
//  JOSE
//
//  Created by Biao Luo on 04/07/2025.
//

import CryptoKit
import Foundation

/// Errors thrown by JWS parsing, signing, and validation.
public enum JWSError: LocalizedError, Equatable {
    /// Invalid JWS format: expected `header.payload.signature`.
    case invalidJWS
    /// Signature verification failed.
    case signatureVerificationFailed
    /// Unsupported algorithm in header.
    case unsupportedAlgorithm
    /// Failed to create signature.
    case signatureCreationFailed
    /// No certificate chain in header.
    case missingCertChain
    /// No trusted certificate for verification.
    case missingTrustedCert
    /// Invalid certificate chain.
    case certChainInvalid
    /// Certificate chain validation failed.
    case certChainVerificationFailed
    /// Failed to create HMAC.
    case hmacCreationFailed
    /// HMAC verification failed.
    case hmacVerificationFailed
    /// Critical JOSE header parameter is not understood by the caller.
    case unsupportedCriticalHeader(String)

    public var errorDescription: String? {
        switch self {
        case .invalidJWS: return "Invalid JWS format: expected header.payload.signature."
        case .signatureVerificationFailed: return "Signature verification failed."
        case .unsupportedAlgorithm: return "Unsupported algorithm in header."
        case .signatureCreationFailed: return "Failed to create signature."
        case .missingCertChain: return "No certificate chain in header."
        case .missingTrustedCert: return "No trusted certificate for verification."
        case .certChainInvalid: return "Invalid certificate chain."
        case .certChainVerificationFailed: return "Certificate chain validation failed."
        case .hmacCreationFailed: return "Failed to create HMAC."
        case .hmacVerificationFailed: return "HMAC verification failed."
        case .unsupportedCriticalHeader(let name): return "Critical JOSE header parameter '\(name)' is not understood."
        }
    }
}

/// Represents a JWS.
///
/// Use this type internally to inspect, validate, or create signed tokens in
/// serialized form.
struct JWS: Equatable {
    /// The protected header.
    let header: JOSEHeader
    /// The payload bytes.
    let payload: Data
    /// The signature bytes.
    let signature: Data
    /// The compact serialization string.
    let compactSerialization: String
    private let signingInput: Data

    /// Parses a JWS string.
    init(compactSerialization: String) throws {
        let components = compactSerialization.components(separatedBy: ".")
        guard components.count == 3 else { throw JWSError.invalidJWS }
        self.compactSerialization = compactSerialization
        guard let headerData = Data(base64URLEncoded: components[0]),
            let header = try? JSONDecoder().decode(JOSEHeader.self, from: headerData),
            let payload = Data(base64URLEncoded: components[1]), let signature = Data(base64URLEncoded: components[2])
        else { throw JWSError.invalidJWS }
        self.header = header
        self.payload = payload
        self.signature = signature
        self.signingInput = components.dropLast().joined(separator: ".").data(using: .ascii) ?? Data()
    }

    fileprivate init(
        header: JOSEHeader,
        payload: Data,
        signature: Data,
        compactSerialization: String,
        signingInput: Data
    ) {
        self.header = header
        self.payload = payload
        self.signature = signature
        self.compactSerialization = compactSerialization
        self.signingInput = signingInput
    }
}

extension JWS {
    private static func signingInput(header: JOSEHeader, payload: Data) throws -> (data: Data, string: String) {
        let jsonEncoder = JSONEncoder()
        jsonEncoder.outputFormatting = .sortedKeys
        let headerData = try jsonEncoder.encode(header)
        let base64URLHeader = headerData.base64URLEncodedString
        let base64URLPayload = payload.base64URLEncodedString
        let signingInputString = "\(base64URLHeader).\(base64URLPayload)"
        let signingInputData = signingInputString.data(using: .ascii)!
        return (signingInputData, signingInputString)
    }

    /// Creates a JWS using an asymmetric signing key.
    static func sign(header: JOSEHeader, payload: Data, key: SecKey) throws -> Self {
        guard header.alg.requiresSecKey else { throw JWSError.unsupportedAlgorithm }
        do {
            let signingInput = try signingInput(header: header, payload: payload)
            let signature = try CryptoSigner.sign(data: signingInput.data, key: key, alg: header.alg).rawPresentation
            let compactSerialization = "\(signingInput.string).\(signature.base64URLEncodedString)"
            return JWS(
                header: header,
                payload: payload,
                signature: signature,
                compactSerialization: compactSerialization,
                signingInput: signingInput.data
            )
        } catch let error as CryptoSignerError {
            switch error {
            case .unsupportedAlgorithm: throw JWSError.unsupportedAlgorithm
            case .signatureCreationFailed: throw JWSError.signatureCreationFailed
            case .signatureVerificationFailed: throw JWSError.signatureVerificationFailed
            }
        } catch { throw JWSError.signatureCreationFailed }
    }
    /// Validates the JWS using a public key.
    func validate(key: SecKey, understoodCriticalHeaders: Set<String> = []) throws {
        do { try header.validateCriticalHeaders(understoodCriticalHeaders: understoodCriticalHeaders) } catch let error
            as UnsupportedCriticalHeaderError
        { throw JWSError.unsupportedCriticalHeader(error.name) }
        guard header.alg.requiresSecKey else { throw JWSError.unsupportedAlgorithm }
        guard let signature = Signature(rawPresentation: signature, algorithm: header.alg) else {
            throw JWSError.signatureVerificationFailed
        }
        do { try CryptoSigner.verifySignature(signature, data: signingInput, key: key, alg: header.alg) } catch let
            error as CryptoSignerError
        {
            switch error {
            case .unsupportedAlgorithm: throw JWSError.unsupportedAlgorithm
            case .signatureCreationFailed, .signatureVerificationFailed: throw JWSError.signatureVerificationFailed
            }
        }
    }

    /// Validates the JWS against a trusted certificate chain.
    func validate(trustedCertificates: [SecCertificate], understoodCriticalHeaders: Set<String> = []) throws {
        do { try header.validateCriticalHeaders(understoodCriticalHeaders: understoodCriticalHeaders) } catch let error
            as UnsupportedCriticalHeaderError
        { throw JWSError.unsupportedCriticalHeader(error.name) }
        guard !trustedCertificates.isEmpty else { throw JWSError.missingTrustedCert }
        guard let certificateChain = header.x509CertificateChain(), !certificateChain.isEmpty else {
            throw JWSError.missingCertChain
        }

        var trust: SecTrust?
        let status = SecTrustCreateWithCertificates(certificateChain as AnyObject, SecPolicyCreateBasicX509(), &trust)
        guard let trust, status == errSecSuccess else { throw JWSError.certChainInvalid }
        SecTrustSetAnchorCertificates(trust, trustedCertificates as CFArray)
        SecTrustSetAnchorCertificatesOnly(trust, true)
        var error: CFError?
        guard SecTrustEvaluateWithError(trust, &error) else { throw JWSError.certChainVerificationFailed }
        guard let publicKey = SecTrustCopyKey(trust) else { throw JWSError.certChainVerificationFailed }
        try validate(key: publicKey, understoodCriticalHeaders: understoodCriticalHeaders)
    }

    /// Creates a JWS using HMAC with a shared secret.
    static func hmac(header: JOSEHeader, payload: Data, key: Data) throws -> Self {
        guard header.alg.isHMACAlgorithm else { throw JWSError.unsupportedAlgorithm }
        do {
            let key = SymmetricKey(data: key)
            let signingInput = try signingInput(header: header, payload: payload)

            let signature: Data =
                switch header.alg {
                case .HS256: Data(HMAC<SHA256>.authenticationCode(for: signingInput.data, using: key))
                case .HS384: Data(HMAC<SHA384>.authenticationCode(for: signingInput.data, using: key))
                case .HS512: Data(HMAC<SHA512>.authenticationCode(for: signingInput.data, using: key))
                default: throw JWSError.unsupportedAlgorithm
                }
            let compactSerialization = "\(signingInput.string).\(signature.base64URLEncodedString)"
            return JWS(
                header: header,
                payload: payload,
                signature: signature,
                compactSerialization: compactSerialization,
                signingInput: signingInput.data
            )
        } catch let error as JWSError { throw error } catch { throw JWSError.hmacCreationFailed }
    }

    /// Validates the JWS using HMAC with a shared secret.
    func validate(key: Data, understoodCriticalHeaders: Set<String> = []) throws {
        do { try header.validateCriticalHeaders(understoodCriticalHeaders: understoodCriticalHeaders) } catch let error
            as UnsupportedCriticalHeaderError
        { throw JWSError.unsupportedCriticalHeader(error.name) }
        guard header.alg.isHMACAlgorithm else { throw JWSError.unsupportedAlgorithm }
        let key = SymmetricKey(data: key)
        let expectedSignature: Data =
            switch header.alg {
            case .HS256: Data(HMAC<SHA256>.authenticationCode(for: signingInput, using: key))
            case .HS384: Data(HMAC<SHA384>.authenticationCode(for: signingInput, using: key))
            case .HS512: Data(HMAC<SHA512>.authenticationCode(for: signingInput, using: key))
            default: throw JWSError.unsupportedAlgorithm
            }
        guard expectedSignature == signature else { throw JWSError.hmacVerificationFailed }
    }
}

@available(*, deprecated, renamed: "JWS")
typealias CompactJWS = JWS
