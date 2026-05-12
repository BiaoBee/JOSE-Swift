import Foundation
import Security
import Testing

@testable import JOSE

struct JWTTests {
    private func makeRSAKeyPair() -> (private: SecKey, public: SecKey) {
        let privateKey = SecKeyCreateRandomKey(
            [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 2048, kSecAttrIsPermanent: false]
                as NSDictionary,
            nil,
        )!
        let publicKey = SecKeyCopyPublicKey(privateKey)!
        return (privateKey, publicKey)
    }

    private func makeECKeyPair(sizeInBits: Int) -> (private: SecKey, public: SecKey) {
        let privateKey = SecKeyCreateRandomKey(
            [
                kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeySizeInBits: sizeInBits,
                kSecAttrIsPermanent: false,
            ] as NSDictionary,
            nil,
        )!
        let publicKey = SecKeyCopyPublicKey(privateKey)!
        return (privateKey, publicKey)
    }

    @Test("Sign, parse, and validate JWT claims with HMAC")
    func signParseValidateHMACJWT() async throws {
        let claims = JWTClaims(
            iss: "https://auth.example.com",
            sub: "user_123",
            aud: "myapp",
            exp: Date(timeIntervalSince1970: 1_752_109_200),
            iat: Date(timeIntervalSince1970: 1_752_105_600),
            privateClaims: ["role": "admin", "department": "engineering"],
        )
        let header = try JOSEHeader(alg: .HS256, typ: "JWT")
        let key = Data("super-secret-key".utf8)

        let signed = try JWT.sign(header: header, claims: claims, key: key)
        let parsed = try JWT.Signed(signed.token)
        let parsedClaims = try parsed.requireClaims()

        #expect(signed.header.alg == .HS256)
        #expect(signed.header.typ == "JWT")
        #expect(parsedClaims.iss == claims.iss)
        #expect(parsedClaims.sub == claims.sub)
        #expect(parsedClaims.aud == claims.aud)
        #expect(parsedClaims.exp == claims.exp)
        #expect(parsedClaims.iat == claims.iat)
        #expect(parsedClaims["role"] as? String == "admin")
        #expect(parsedClaims["department"] as? String == "engineering")
        try signed.validate(key: key)
    }

    @Test("Sign, parse, and validate JWT claims with RSA")
    func signParseValidateRSAJWT() async throws {
        let keys = makeRSAKeyPair()
        let claims = JWTClaims(
            iss: "https://auth.example.com",
            sub: "user_abc",
            aud: "myapp",
            exp: Date(timeIntervalSince1970: 1_752_109_200),
        )
        let header = try JOSEHeader(alg: .RS256, typ: "JWT")

        let signed = try JWT.sign(header: header, claims: claims, key: keys.private)
        let parsed = try JWT.Signed(signed.token)
        let parsedClaims = try parsed.requireClaims()

        #expect(signed.header.alg == .RS256)
        #expect(parsedClaims.iss == claims.iss)
        #expect(parsedClaims.sub == claims.sub)
        #expect(parsedClaims.aud == claims.aud)
        #expect(parsedClaims.exp == claims.exp)
        try signed.validate(key: keys.public)
    }

    @Test("Sign plain-text JWT payload with HMAC")
    func signPlainTextPayloadWithHMAC() async throws {
        let header = try JOSEHeader(alg: .HS256, typ: "JWT")
        let key = Data("super-secret-key".utf8)
        let plainText = "header.payload.signature"
        let payload = Data(plainText.utf8)

        let signed = try JWT.sign(header: header, payload: payload, key: key)
        let parsed = try JWT.Signed(signed.token)

        #expect(parsed.header.alg == .HS256)
        #expect(parsed.payload == payload)
        #expect(String(data: parsed.payload, encoding: .utf8) == plainText)
        try parsed.validate(key: key)
    }

    @Test("Sign raw JWT payload with RSA")
    func signRawPayloadWithRSA() async throws {
        let keys = makeRSAKeyPair()
        let header = try JOSEHeader(alg: .RS256, typ: "JWT")
        let payload = Data([0x01, 0x02, 0x03, 0x04])

        let signed = try JWT.sign(header: header, payload: payload, key: keys.private)
        let parsed = try JWT.Signed(signed.token)

        #expect(parsed.header.alg == .RS256)
        #expect(parsed.payload == payload)
        try parsed.validate(key: keys.public)
    }

    @Test("Reject unsupported critical header by default")
    func rejectUnsupportedCriticalHeaderByDefault() async throws {
        let keys = makeRSAKeyPair()
        let claims = JWTClaims(sub: "user_abc")
        let header = try JOSEHeader(
            alg: .RS256,
            typ: "JWT",
            crit: ["tenant"],
            customParameters: ["tenant": "internal"],
        )

        let signed = try JWT.sign(header: header, claims: claims, key: keys.private)

        do {
            try signed.validate(key: keys.public)
            #expect(Bool(false))
        } catch let error as JWSError { #expect(error == .unsupportedCriticalHeader("tenant")) } catch {
            #expect(Bool(false))
        }
    }

    @Test("Allow understood critical header during validation")
    func allowUnderstoodCriticalHeaderDuringValidation() async throws {
        let keys = makeRSAKeyPair()
        let claims = JWTClaims(sub: "user_abc")
        let header = try JOSEHeader(
            alg: .RS256,
            typ: "JWT",
            crit: ["tenant"],
            customParameters: ["tenant": "internal"],
        )

        let signed = try JWT.sign(header: header, claims: claims, key: keys.private)

        try signed.validate(key: keys.public, understoodCriticalHeaders: ["tenant"])
    }

    @Test("Encrypt, parse, and decrypt JWT claims with direct encryption")
    func encryptParseDecryptDirectJWT() async throws {
        let claims = JWTClaims(
            iss: "https://auth.example.com",
            sub: "user_123",
            aud: "myapp",
            exp: Date(timeIntervalSince1970: 1_752_109_200),
            iat: Date(timeIntervalSince1970: 1_752_105_600),
            privateClaims: ["role": "admin", "department": "engineering"],
        )
        let header = try JOSEHeader(alg: .DIR, typ: "JWT", enc: "A256GCM")
        let key = Data((0..<32).map(UInt8.init))

        let encrypted = try JWT.encrypt(header: header, claims: claims, key: key)
        let parsed = try JWT.Encrypted(encrypted.token)
        let decryptedClaims = try parsed.decryptClaims(key: key)
        let decryptedData = try parsed.decryptData(key: key)
        let encodedClaims = try JWT.encodeClaims(claims)

        #expect(parsed.header.alg == .DIR)
        #expect(parsed.header.typ == "JWT")
        #expect(parsed.header.enc == "A256GCM")
        #expect(decryptedClaims.iss == claims.iss)
        #expect(decryptedClaims.sub == claims.sub)
        #expect(decryptedClaims.aud == claims.aud)
        #expect(decryptedClaims.exp == claims.exp)
        #expect(decryptedClaims.iat == claims.iat)
        #expect(decryptedClaims["role"] as? String == "admin")
        #expect(decryptedClaims["department"] as? String == "engineering")
        #expect(decryptedData == encodedClaims)
    }

    @Test("Encrypt, parse, and decrypt JWT claims with RSA key management")
    func encryptParseDecryptRSAJWT() async throws {
        let keys = makeRSAKeyPair()
        let claims = JWTClaims(
            sub: "user_abc",
            aud: "myapp",
            privateClaims: ["scope": "read:messages"],
        )
        let header = try JOSEHeader(alg: .RSA_OAEP_256, typ: "JWT", enc: "A256GCM")

        let encrypted = try JWT.encrypt(header: header, claims: claims, key: keys.public)
        let parsed = try JWT.Encrypted(encrypted.token)
        let decryptedClaims = try parsed.decryptClaims(key: keys.private)

        #expect(parsed.header.alg == .RSA_OAEP_256)
        #expect(parsed.header.enc == "A256GCM")
        #expect(decryptedClaims.sub == claims.sub)
        #expect(decryptedClaims.aud == claims.aud)
        #expect(decryptedClaims["scope"] as? String == "read:messages")
    }

    @Test("Encrypt, parse, and decrypt JWT claims with ECDH key management")
    func encryptParseDecryptECDHJWT() async throws {
        let keys = makeECKeyPair(sizeInBits: 256)
        let claims = JWTClaims(
            sub: "user_abc",
            privateClaims: ["tenant": "internal"],
        )
        let header = try JOSEHeader(alg: .ECDH_ES, typ: "JWT", enc: "A256GCM")

        let encrypted = try JWT.encrypt(header: header, claims: claims, key: keys.public)
        let parsed = try JWT.Encrypted(encrypted.token)
        let decryptedClaims = try parsed.decryptClaims(key: keys.private)

        #expect(parsed.header.alg == .ECDH_ES)
        #expect(parsed.header.enc == "A256GCM")
        #expect(parsed.header.epk != nil)
        #expect(decryptedClaims.sub == claims.sub)
        #expect(decryptedClaims["tenant"] as? String == "internal")
    }

    @Test("Encrypt plain-text JWT payload for nested JWTs")
    func encryptPlainTextPayloadForNestedJWT() async throws {
        let signingHeader = try JOSEHeader(alg: .HS256, typ: "JWT")
        let encryptionHeader = try JOSEHeader(alg: .DIR, cty: "JWT", enc: "A256GCM")
        let claims = JWTClaims(sub: "user_123", privateClaims: ["role": "admin"])
        let signingKey = Data("super-secret-key".utf8)
        let encryptionKey = Data((0..<32).map(UInt8.init))

        let signed = try JWT.sign(header: signingHeader, claims: claims, key: signingKey)
        let encrypted = try JWT.encrypt(header: encryptionHeader, data: Data(signed.token.utf8), key: encryptionKey)
        let parsed = try JWT.Encrypted(encrypted.token)
        let decryptedData = try parsed.decryptData(key: encryptionKey)

        #expect(parsed.header.cty == "JWT")
        #expect(String(data: decryptedData, encoding: .utf8) == signed.token)
    }

    @Test("Encrypt raw payload data with RSA key management")
    func encryptRawPayloadDataWithRSA() async throws {
        let keys = makeRSAKeyPair()
        let header = try JOSEHeader(alg: .RSA_OAEP_256, enc: "A256GCM")
        let payload = Data([0xde, 0xad, 0xbe, 0xef])

        let encrypted = try JWT.encrypt(header: header, data: payload, key: keys.public)
        let parsed = try JWT.Encrypted(encrypted.token)
        let decryptedData = try parsed.decryptData(key: keys.private)

        #expect(decryptedData == payload)
    }

    @Test("Reject unsupported critical header during encrypted JWT decryption by default")
    func rejectUnsupportedCriticalHeaderDuringEncryptedJWTDecryption() async throws {
        let header = try JOSEHeader(
            alg: .DIR,
            typ: "JWT",
            crit: ["tenant"],
            enc: "A256GCM",
            customParameters: ["tenant": "internal"],
        )
        let claims = JWTClaims(sub: "user_123")
        let key = Data((0..<32).map(UInt8.init))

        let encrypted = try JWT.encrypt(header: header, claims: claims, key: key)
        let parsed = try JWT.Encrypted(encrypted.token)

        do {
            _ = try parsed.decryptClaims(key: key)
            #expect(Bool(false))
        } catch let error as JWEError { #expect(error == .unsupportedCriticalHeader("tenant")) } catch {
            #expect(Bool(false))
        }
    }

    @Test("Allow understood critical header during encrypted JWT decryption")
    func allowUnderstoodCriticalHeaderDuringEncryptedJWTDecryption() async throws {
        let header = try JOSEHeader(
            alg: .DIR,
            typ: "JWT",
            crit: ["tenant"],
            enc: "A256GCM",
            customParameters: ["tenant": "internal"],
        )
        let claims = JWTClaims(sub: "user_123")
        let key = Data((0..<32).map(UInt8.init))

        let encrypted = try JWT.encrypt(header: header, claims: claims, key: key)
        let parsed = try JWT.Encrypted(encrypted.token)
        let decryptedClaims = try parsed.decryptClaims(key: key, understoodCriticalHeaders: ["tenant"])

        #expect(decryptedClaims.sub == claims.sub)
    }

    @Test("Reject claims decoding for plain text encrypted payload")
    func rejectClaimsDecodingForPlainTextEncryptedPayload() async throws {
        let key = Data((0..<32).map(UInt8.init))
        let header = try JOSEHeader(alg: .DIR, typ: "JWT", enc: "A256GCM")
        let plainText = "header.payload.signature"

        let jwe = try JWE.encrypt(plaintext: Data(plainText.utf8), key: key, header: header)
        let parsed = try JWT.Encrypted(jwe.compactSerialization)
        let decryptedData = try parsed.decryptData(key: key)

        #expect(String(data: decryptedData, encoding: .utf8) == plainText)

        do {
            _ = try parsed.decryptClaims(key: key)
            #expect(Bool(false))
        } catch is DecodingError {
            #expect(Bool(true))
        } catch {
            #expect(Bool(false))
        }
    }
}
