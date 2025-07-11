//
//  Crypto.swift
//  JOSE
//
//  Created by Biao Luo on 11/07/2025.
//

import Foundation
import Security

struct Crypto {
    static func sign(data: Data, key: SecKey, alg: JWA) throws -> Data {
        let algorithm: SecKeyAlgorithm = switch alg {
        case .ES256: SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
        case .ES384: SecKeyAlgorithm.ecdsaSignatureMessageX962SHA384
        case .ES512: SecKeyAlgorithm.ecdsaSignatureMessageX962SHA512
        default:
            throw NSError(domain: "", code: 0)
        }

        guard SecKeyIsAlgorithmSupported(key, .sign, algorithm) else {
            throw NSError(domain: "", code: 0)
        }
        
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(key, algorithm, data as CFData, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return signature as Data
    }
}
