//
//  JWEContentEncryption.swift
//  JOSE
//
//  Created by Biao Luo on 23/04/2026.
//

import CryptoKit
import Foundation

enum JWEContentEncryptionAlgorithm: String, Codable {
    case A128GCM
    case A256GCM

    var keyLengthInBytes: Int {
        switch self {
        case .A128GCM: 16
        case .A256GCM: 32
        }
    }

    var nonceLengthInBytes: Int { 12 }
}

enum JWEContentCipher {
    static func encrypt(
        plaintext: Data,
        key: Data,
        iv: Data,
        aad: Data,
        algorithm: JWEContentEncryptionAlgorithm
    ) throws -> (ciphertext: Data, tag: Data) {
        guard key.count == algorithm.keyLengthInBytes else { throw JWEError.invalidKey }
        guard iv.count == algorithm.nonceLengthInBytes, let nonce = try? AES.GCM.Nonce(data: iv) else {
            throw JWEError.invalidKey
        }

        let symmetricKey = SymmetricKey(data: key)
        let sealedBox: AES.GCM.SealedBox
        do { sealedBox = try AES.GCM.seal(plaintext, using: symmetricKey, nonce: nonce, authenticating: aad) } catch {
            throw JWEError.encryptionFailed
        }
        return (ciphertext: sealedBox.ciphertext, tag: sealedBox.tag)
    }

    static func decrypt(
        ciphertext: Data,
        tag: Data,
        key: Data,
        iv: Data,
        aad: Data,
        algorithm: JWEContentEncryptionAlgorithm
    ) throws -> Data {
        guard key.count == algorithm.keyLengthInBytes else { throw JWEError.invalidKey }
        guard iv.count == algorithm.nonceLengthInBytes, let nonce = try? AES.GCM.Nonce(data: iv) else {
            throw JWEError.invalidKey
        }
        guard tag.count == 16 else { throw JWEError.invalidTag }

        let symmetricKey = SymmetricKey(data: key)
        do {
            let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
            return try AES.GCM.open(sealedBox, using: symmetricKey, authenticating: aad)
        } catch let error as CryptoKitError {
            switch error {
            case .authenticationFailure: throw JWEError.invalidTag
            default: throw JWEError.decryptionFailed
            }
        } catch { throw JWEError.decryptionFailed }
    }
}
