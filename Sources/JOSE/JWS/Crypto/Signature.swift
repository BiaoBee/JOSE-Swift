//
//  ECDSASignature.swift
//  JOSE
//
//  Created by Biao Luo on 13/07/2025.
//

import CryptoKit
import Foundation

struct Signature {
    let rawPresentation: Data
    let derPresentation: Data
    let algorithm: JWA

    /// Initializes from a raw (r||s) signature for ECDSA, or from the signature
    /// bytes directly for RSA.
    init?(rawPresentation: Data, algorithm: JWA) {
        guard algorithm.isECDSAAlgorithm || algorithm.isRSAAlgorithm else { return nil }
        self.rawPresentation = rawPresentation
        self.algorithm = algorithm

        if algorithm.isECDSAAlgorithm {
            guard let derPresentation = Self.convertRawToDER(rawPresentation, algorithm: algorithm) else { return nil }
            self.derPresentation = derPresentation
        } else {
            self.derPresentation = rawPresentation
        }
    }

    /// Initializes from a DER-encoded signature for ECDSA, or from the
    /// signature bytes directly for RSA.
    init?(derPresentation: Data, algorithm: JWA) {
        guard algorithm.isECDSAAlgorithm || algorithm.isRSAAlgorithm else { return nil }
        self.derPresentation = derPresentation
        self.algorithm = algorithm
        if algorithm.isECDSAAlgorithm {
            guard let rawPresentation = Self.convertDERToRaw(derPresentation, algorithm: algorithm) else { return nil }
            self.rawPresentation = rawPresentation
        } else {
            self.rawPresentation = derPresentation
        }
    }

    // MARK: - Conversion Functions
    private static func convertRawToDER(_ rawRepresentation: Data, algorithm: JWA) -> Data? {
        switch algorithm {
        case .ES256: return try? P256.Signing.ECDSASignature(rawRepresentation: rawRepresentation).derRepresentation
        case .ES384: return try? P384.Signing.ECDSASignature(rawRepresentation: rawRepresentation).derRepresentation
        case .ES512: return try? P521.Signing.ECDSASignature(rawRepresentation: rawRepresentation).derRepresentation
        default: return nil
        }
    }

    private static func convertDERToRaw(_ derRepresentation: Data, algorithm: JWA) -> Data? {
        switch algorithm {
        case .ES256: return try? P256.Signing.ECDSASignature(derRepresentation: derRepresentation).rawRepresentation
        case .ES384: return try? P384.Signing.ECDSASignature(derRepresentation: derRepresentation).rawRepresentation
        case .ES512: return try? P521.Signing.ECDSASignature(derRepresentation: derRepresentation).rawRepresentation
        default: return nil
        }
    }
}
