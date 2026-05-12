//
//  JWE.swift
//  JOSE
//
//  Created by Biao Luo on 23/04/2026.
//

import Foundation
import Security

extension JOSEHeader {
    func validatedForDirectJWE() throws -> JWEContentEncryptionAlgorithm {
        guard alg == .DIR, let enc = enc, let encryptionAlgorithm = JWEContentEncryptionAlgorithm(rawValue: enc) else {
            throw JWEError.unsupportedAlgorithm
        }
        guard zip == nil else { throw JWEError.unsupportedAlgorithm }
        return encryptionAlgorithm
    }

    func validatedForRSAJWE() throws -> JWEContentEncryptionAlgorithm {
        guard alg.isRSAKeyManagementAlgorithm, let enc = enc,
            let encryptionAlgorithm = JWEContentEncryptionAlgorithm(rawValue: enc)
        else { throw JWEError.unsupportedAlgorithm }
        guard zip == nil else { throw JWEError.unsupportedAlgorithm }
        return encryptionAlgorithm
    }

    func validatedForECDHJWE() throws -> JWEContentEncryptionAlgorithm {
        guard alg.isECDHKeyManagementAlgorithm, let enc,
            let encryptionAlgorithm = JWEContentEncryptionAlgorithm(rawValue: enc)
        else { throw JWEError.unsupportedAlgorithm }
        guard zip == nil else { throw JWEError.unsupportedAlgorithm }
        return encryptionAlgorithm
    }
}

/// Represents a JWE.
///
/// Use this type internally to inspect, encrypt, or decrypt tokens in
/// serialized form.
struct JWE: Equatable {
    /// The protected header.
    let header: JOSEHeader
    /// The encrypted key segment.
    let encryptedKey: Data
    /// The initialization vector.
    let initializationVector: Data
    /// The ciphertext.
    let ciphertext: Data
    /// The authentication tag.
    let tag: Data
    /// The compact serialization string.
    let compactSerialization: String

    private let protectedHeaderSegment: String

    /// Parses a JWE string.
    init(compactSerialization: String) throws {
        let components = compactSerialization.components(separatedBy: ".")
        guard components.count == 5 else { throw JWEError.invalidJWE }

        self.compactSerialization = compactSerialization
        self.protectedHeaderSegment = components[0]

        guard let headerData = Data(base64URLEncoded: components[0]),
            let header = try? JSONDecoder().decode(JOSEHeader.self, from: headerData),
            let encryptedKey = Data(base64URLEncoded: components[1]), let iv = Data(base64URLEncoded: components[2]),
            let ciphertext = Data(base64URLEncoded: components[3]), let tag = Data(base64URLEncoded: components[4])
        else { throw JWEError.invalidJWE }

        guard let enc = header.enc.flatMap(JWEContentEncryptionAlgorithm.init(rawValue:)) else {
            throw JWEError.unsupportedAlgorithm
        }
        guard tag.count == 16 else { throw JWEError.invalidTag }
        guard iv.count == enc.nonceLengthInBytes else { throw JWEError.invalidKey }

        self.header = header
        self.encryptedKey = encryptedKey
        self.initializationVector = iv
        self.ciphertext = ciphertext
        self.tag = tag
    }

    init(
        header: JOSEHeader,
        encryptedKey: Data,
        initializationVector: Data,
        ciphertext: Data,
        tag: Data,
        protectedHeaderSegment: String
    ) {
        self.header = header
        self.encryptedKey = encryptedKey
        self.initializationVector = initializationVector
        self.ciphertext = ciphertext
        self.tag = tag
        self.protectedHeaderSegment = protectedHeaderSegment
        self.compactSerialization = [
            protectedHeaderSegment, encryptedKey.base64URLEncodedString, initializationVector.base64URLEncodedString,
            ciphertext.base64URLEncodedString, tag.base64URLEncodedString,
        ].joined(separator: ".")
    }

    var aad: Data { protectedHeaderSegment.data(using: .ascii) ?? Data() }

    /// Encrypts plaintext into a JWE using RSA or ECDH key management.
    static func encrypt(plaintext: Data, key: SecKey, header: JOSEHeader) throws -> Self {
        if header.alg.isRSAKeyManagementAlgorithm {
            return try encryptRSA(plaintext: plaintext, key: key, header: header)
        }

        if header.alg.isECDHKeyManagementAlgorithm {
            return try encryptECDH(plaintext: plaintext, key: key, header: header)
        }

        throw JWEError.unsupportedAlgorithm
    }

    /// Encrypts plaintext into a JWE using direct symmetric encryption (`alg = dir`).
    static func encrypt(plaintext: Data, key: Data, header: JOSEHeader) throws -> Self {
        let contentEncryption = try header.validatedForDirectJWE()
        guard key.count == contentEncryption.keyLengthInBytes else { throw JWEError.invalidKey }

        let protectedHeader = try encodedProtectedHeader(header)
        let iv = try secureRandomBytes(count: contentEncryption.nonceLengthInBytes)
        let aad = protectedHeader.data(using: .ascii) ?? Data()
        let result = try JWEContentCipher.encrypt(
            plaintext: plaintext,
            key: key,
            iv: iv,
            aad: aad,
            algorithm: contentEncryption
        )

        return JWE(
            header: header,
            encryptedKey: Data(),
            initializationVector: iv,
            ciphertext: result.ciphertext,
            tag: result.tag,
            protectedHeaderSegment: protectedHeader
        )
    }

    private static func encryptRSA(plaintext: Data, key: SecKey, header: JOSEHeader) throws -> Self {
        let contentEncryption = try header.validatedForRSAJWE()
        let cek = try secureRandomBytes(count: contentEncryption.keyLengthInBytes)
        let protectedHeader = try encodedProtectedHeader(header)
        let iv = try secureRandomBytes(count: contentEncryption.nonceLengthInBytes)
        let aad = protectedHeader.data(using: .ascii) ?? Data()
        let result = try JWEContentCipher.encrypt(
            plaintext: plaintext,
            key: cek,
            iv: iv,
            aad: aad,
            algorithm: contentEncryption
        )
        let encryptedKey = try RSAKeyManagement.wrap(cek: cek, with: key, algorithm: header.alg)

        return JWE(
            header: header,
            encryptedKey: encryptedKey,
            initializationVector: iv,
            ciphertext: result.ciphertext,
            tag: result.tag,
            protectedHeaderSegment: protectedHeader
        )
    }

    private static func encryptECDH(plaintext: Data, key: SecKey, header: JOSEHeader) throws -> Self {
        let contentEncryption = try header.validatedForECDHJWE()
        let result = try ECDHKeyManagement.wrap(header: header, recipientKey: key, contentEncryption: contentEncryption)
        let protectedHeader = try encodedProtectedHeader(result.header)
        let iv = try secureRandomBytes(count: contentEncryption.nonceLengthInBytes)
        let aad = protectedHeader.data(using: .ascii) ?? Data()
        let encrypted = try JWEContentCipher.encrypt(
            plaintext: plaintext,
            key: result.cek,
            iv: iv,
            aad: aad,
            algorithm: contentEncryption
        )

        return JWE(
            header: result.header,
            encryptedKey: result.encryptedKey,
            initializationVector: iv,
            ciphertext: encrypted.ciphertext,
            tag: encrypted.tag,
            protectedHeaderSegment: protectedHeader
        )
    }

    /// Decrypts a JWE using RSA or ECDH key management.
    static func decrypt(
        compactSerialization: String,
        key: SecKey,
        understoodCriticalHeaders: Set<String> = []
    ) throws -> Data {
        let jwe = try JWE(compactSerialization: compactSerialization)
        do { try jwe.header.validateCriticalHeaders(understoodCriticalHeaders: understoodCriticalHeaders) } catch let
            error as UnsupportedCriticalHeaderError
        { throw JWEError.unsupportedCriticalHeader(error.name) }
        if jwe.header.alg.isRSAKeyManagementAlgorithm { return try decryptRSA(jwe: jwe, key: key) }

        if jwe.header.alg.isECDHKeyManagementAlgorithm { return try decryptECDH(jwe: jwe, key: key) }

        throw JWEError.unsupportedAlgorithm
    }

    /// Decrypts a JWE produced with direct symmetric encryption (`alg = dir`).
    static func decrypt(
        compactSerialization: String,
        key: Data,
        understoodCriticalHeaders: Set<String> = []
    ) throws -> Data {
        let jwe = try JWE(compactSerialization: compactSerialization)
        do { try jwe.header.validateCriticalHeaders(understoodCriticalHeaders: understoodCriticalHeaders) } catch let
            error as UnsupportedCriticalHeaderError
        { throw JWEError.unsupportedCriticalHeader(error.name) }
        let contentEncryption = try jwe.header.validatedForDirectJWE()
        guard key.count == contentEncryption.keyLengthInBytes else { throw JWEError.invalidKey }

        return try JWEContentCipher.decrypt(
            ciphertext: jwe.ciphertext,
            tag: jwe.tag,
            key: key,
            iv: jwe.initializationVector,
            aad: jwe.aad,
            algorithm: contentEncryption
        )
    }

    private static func decryptRSA(jwe: JWE, key: SecKey) throws -> Data {
        let contentEncryption = try jwe.header.validatedForRSAJWE()
        let cek = try RSAKeyManagement.unwrap(encryptedKey: jwe.encryptedKey, with: key, algorithm: jwe.header.alg)

        return try JWEContentCipher.decrypt(
            ciphertext: jwe.ciphertext,
            tag: jwe.tag,
            key: cek,
            iv: jwe.initializationVector,
            aad: jwe.aad,
            algorithm: contentEncryption
        )
    }

    private static func decryptECDH(jwe: JWE, key: SecKey) throws -> Data {
        let contentEncryption = try jwe.header.validatedForECDHJWE()
        let cek = try ECDHKeyManagement.unwrap(
            encryptedKey: jwe.encryptedKey,
            header: jwe.header,
            recipientKey: key,
            contentEncryption: contentEncryption
        )

        return try JWEContentCipher.decrypt(
            ciphertext: jwe.ciphertext,
            tag: jwe.tag,
            key: cek,
            iv: jwe.initializationVector,
            aad: jwe.aad,
            algorithm: contentEncryption
        )
    }

    private static func encodedProtectedHeader(_ header: JOSEHeader) throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        let headerData = try encoder.encode(header)
        return headerData.base64URLEncodedString
    }
}
