//
//  ECDHKeyManagement.swift
//  JOSE
//
//  Created by Biao Luo on 23/04/2026.
//

import Foundation
import Security

enum ECDHKeyManagement {
    static func wrap(
        header: JOSEHeader,
        recipientKey: SecKey,
        contentEncryption: JWEContentEncryptionAlgorithm
    ) throws -> (cek: Data, encryptedKey: Data, header: JOSEHeader) {
        guard header.alg.isECDHKeyManagementAlgorithm else { throw JWEError.unsupportedAlgorithm }
        guard header.zip == nil else { throw JWEError.unsupportedAlgorithm }
        guard let recipientCurve = curve(for: recipientKey) else { throw JWEError.invalidKey }

        let ephemeralKeyPair = try generateEphemeralKeyPair(curve: recipientCurve)
        guard let epk = JWK.ec(publicKey: ephemeralKeyPair.public) else { throw JWEError.invalidKey }

        var fullHeader = header
        fullHeader.epk = epk
        let partyUInfo = header.apu.flatMap(Data.init(base64URLEncoded:))
        let partyVInfo = header.apv.flatMap(Data.init(base64URLEncoded:))
        let sharedInfo = buildOtherInfo(
            algorithmID: header.alg == .ECDH_ES ? contentEncryption.rawValue : header.alg.rawValue,
            keyDataLengthBits: keyLengthBits(for: header.alg, enc: contentEncryption),
            partyUInfo: partyUInfo,
            partyVInfo: partyVInfo
        )

        let derivedKey = try deriveKey(
            privateKey: ephemeralKeyPair.private,
            publicKey: recipientKey,
            sharedInfo: sharedInfo,
            outputByteCount: keyLengthBytes(for: header.alg, enc: contentEncryption)
        )

        if header.alg == .ECDH_ES { return (derivedKey, Data(), fullHeader) }

        let cek = try secureRandomBytes(count: contentEncryption.keyLengthInBytes)
        let encryptedKey = try AESKeyWrap.wrap(keyToWrap: cek, kek: derivedKey)
        return (cek, encryptedKey, fullHeader)
    }

    static func unwrap(
        encryptedKey: Data,
        header: JOSEHeader,
        recipientKey: SecKey,
        contentEncryption: JWEContentEncryptionAlgorithm
    ) throws -> Data {
        guard header.alg.isECDHKeyManagementAlgorithm else { throw JWEError.unsupportedAlgorithm }
        guard header.zip == nil else { throw JWEError.unsupportedAlgorithm }
        guard let recipientCurve = curve(for: recipientKey), let epk = header.epk?.publicECKey(),
            let epkCurve = curve(for: epk), recipientCurve == epkCurve
        else { throw JWEError.invalidHeader }

        let partyUInfo = header.apu.flatMap(Data.init(base64URLEncoded:))
        let partyVInfo = header.apv.flatMap(Data.init(base64URLEncoded:))
        let sharedInfo = buildOtherInfo(
            algorithmID: header.alg == .ECDH_ES ? contentEncryption.rawValue : header.alg.rawValue,
            keyDataLengthBits: keyLengthBits(for: header.alg, enc: contentEncryption),
            partyUInfo: partyUInfo,
            partyVInfo: partyVInfo
        )

        let derivedKey = try deriveKey(
            privateKey: recipientKey,
            publicKey: epk,
            sharedInfo: sharedInfo,
            outputByteCount: keyLengthBytes(for: header.alg, enc: contentEncryption)
        )

        if header.alg == .ECDH_ES { return derivedKey }

        return try AESKeyWrap.unwrap(wrappedKey: encryptedKey, kek: derivedKey)
    }

    private static func deriveKey(
        privateKey: SecKey,
        publicKey: SecKey,
        sharedInfo: Data,
        outputByteCount: Int
    ) throws -> Data {
        let parameters: [String: Any] = [
            SecKeyKeyExchangeParameter.requestedSize.rawValue as String: outputByteCount,
            SecKeyKeyExchangeParameter.sharedInfo.rawValue as String: sharedInfo,
        ]
        var error: Unmanaged<CFError>?
        guard
            let derived = SecKeyCopyKeyExchangeResult(
                privateKey,
                .ecdhKeyExchangeStandardX963SHA256,
                publicKey,
                parameters as CFDictionary,
                &error
            )
        else {
            _ = error?.takeRetainedValue()
            throw JWEError.decryptionFailed
        }
        return derived as Data
    }

    private static func buildOtherInfo(
        algorithmID: String,
        keyDataLengthBits: Int,
        partyUInfo: Data?,
        partyVInfo: Data?
    ) -> Data {
        var otherInfo = Data()
        otherInfo.append(lengthPrefixed(Data(algorithmID.utf8)))
        otherInfo.append(lengthPrefixed(partyUInfo ?? Data()))
        otherInfo.append(lengthPrefixed(partyVInfo ?? Data()))
        otherInfo.append(contentsOf: UInt32(keyDataLengthBits).bigEndianBytes)
        return otherInfo
    }

    private static func lengthPrefixed(_ data: Data) -> Data {
        var prefixed = Data()
        prefixed.append(contentsOf: UInt32(data.count).bigEndianBytes)
        prefixed.append(data)
        return prefixed
    }

    private static func keyLengthBytes(for alg: JWA, enc: JWEContentEncryptionAlgorithm) -> Int {
        alg == .ECDH_ES ? enc.keyLengthInBytes : alg.ecdhKeyManagementDerivedKeyLengthInBytes ?? 0
    }

    private static func keyLengthBits(for alg: JWA, enc: JWEContentEncryptionAlgorithm) -> Int {
        keyLengthBytes(for: alg, enc: enc) * 8
    }

    private static func curve(for key: SecKey) -> JWK.Curve? {
        guard let attributes = SecKeyCopyAttributes(key) as? [CFString: Any],
            let keyType = attributes[kSecAttrKeyType] as? String,
            keyType == (kSecAttrKeyTypeECSECPrimeRandom as String),
            let keySize = attributes[kSecAttrKeySizeInBits] as? Int
        else { return nil }

        switch keySize {
        case 256: return .P256
        case 384: return .P384
        case 521: return .P521
        default: return nil
        }
    }

    private static func generateEphemeralKeyPair(curve: JWK.Curve) throws -> (private: SecKey, public: SecKey) {
        let privateKey = SecKeyCreateRandomKey(
            [
                kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeySizeInBits: curve.keySize,
                kSecAttrIsPermanent: false,
            ] as NSDictionary,
            nil
        )
        guard let privateKey, let publicKey = SecKeyCopyPublicKey(privateKey) else { throw JWEError.encryptionFailed }
        return (privateKey, publicKey)
    }
}

extension UInt32 { fileprivate var bigEndianBytes: [UInt8] { withUnsafeBytes(of: bigEndian, Array.init) } }
