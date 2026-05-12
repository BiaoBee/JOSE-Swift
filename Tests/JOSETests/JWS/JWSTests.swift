//
//  JWSTests.swift
//  JOSE
//
//  Created by Biao Luo on 11/07/2025.
//

import CryptoKit
import Foundation
import Security
import Testing

@testable import JOSE

struct JWSTests {
    private func stripped(_ string: String) -> String {
        string.replacingOccurrences(of: "\\s+", with: "", options: .regularExpression)
    }

    private func makeECKeyPair() throws -> (private: SecKey, public: SecKey) {
        let privateKey = SecKeyCreateRandomKey(
            [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeySizeInBits: 256, kSecAttrIsPermanent: false]
                as NSDictionary,
            nil
        )!
        let publicKey = SecKeyCopyPublicKey(privateKey)!
        return (privateKey, publicKey)
    }

    private func makeRSAKeyPair() throws -> (private: SecKey, public: SecKey) {
        let privateKey = SecKeyCreateRandomKey(
            [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 2048, kSecAttrIsPermanent: false]
                as NSDictionary,
            nil
        )!
        let publicKey = SecKeyCopyPublicKey(privateKey)!
        return (privateKey, publicKey)
    }

    @Test("RFC 7515 A.3 ECDSA JWS")
    func validateRFCES256JWS() async throws {
        let jwk = JWK.ec(
            crv: .P256,
            x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
        )
        let publicKey = jwk.publicECKey()!
        let jws = try JWS(
            compactSerialization: stripped(
                """
                eyJhbGciOiJFUzI1NiJ9.
                eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt
                cGxlLmNvbS9pc19yb290Ijp0cnVlfQ.
                DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA
                pmWQxfKTUJqPP3-Kg6NU1Q
                """
            )
        )
        try jws.validate(key: publicKey)
        let claims = try JSONDecoder().decode(JWTClaims.self, from: jws.payload)
        #expect(claims.iss == "joe")
        #expect(claims.exp == Date(timeIntervalSince1970: 1_300_819_380))
        #expect(claims["http://example.com/is_root"] as? Bool == true)
    }

    @Test("Create and validate ECDSA JWS")
    func createAndValidateECDSAJWS() async throws {
        let keys = try makeECKeyPair()
        let jws = try JWS.sign(
            header: try JOSEHeader(alg: .ES256),
            payload: "random payload".data(using: .utf8)!,
            key: keys.private
        )
        try jws.validate(key: keys.public)
    }

    @Test("RFC 7515 A.2 RSA JWS")
    func validateRFCRS256JWS() async throws {
        let privateJWK = JWK.rsa(
            n: stripped(
                """
                ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx
                HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs
                D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH
                SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV
                MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8
                NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ
                """
            ),
            e: "AQAB",
            d: stripped(
                """
                Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I
                jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0
                BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn
                439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT
                CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh
                BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ
                """
            ),
            p: stripped(
                """
                4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdi
                YrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPG
                BY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc
                """
            ),
            q: stripped(
                """
                uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxa
                ewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA
                -njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc
                """
            ),
            dp: stripped(
                """
                BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3Q
                CLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb
                34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0
                """
            ),
            dq: stripped(
                """
                h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa
                7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-ky
                NlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU
                """
            ),
            qi: stripped(
                """
                IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2o
                y26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLU
                W0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U
                """
            )
        )
        let privateKey = privateJWK.privateRSAKey()!
        let publicKey = SecKeyCopyPublicKey(privateKey)!
        let jws = try JWS(
            compactSerialization: stripped(
                """
                eyJhbGciOiJSUzI1NiJ9.
                eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt
                cGxlLmNvbS9pc19yb290Ijp0cnVlfQ.
                cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7
                AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4
                BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K
                0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv
                hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB
                p0igcN_IoypGlUPQGe77Rw
                """
            )
        )
        try jws.validate(key: publicKey)
        let claims = try JSONDecoder().decode(JWTClaims.self, from: jws.payload)
        #expect(claims.iss == "joe")
        #expect(claims.exp == Date(timeIntervalSince1970: 1_300_819_380))
        #expect(claims["http://example.com/is_root"] as? Bool == true)
    }

    @Test("RFC 7515 A.4 ES512 JWS")
    func validateRFCES512JWS() async throws {
        let jwk = JWK.ec(
            crv: .P521,
            x: stripped(
                """
                AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_
                NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk
                """
            ),
            y: stripped(
                """
                ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDl
                y79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2
                """
            ),
            d: stripped(
                """
                AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPA
                xerEzgdRhajnu0ferB0d53vM9mE15j2C
                """
            )
        )
        let publicKey = jwk.publicECKey()!
        let jws = try JWS(
            compactSerialization: stripped(
                """
                eyJhbGciOiJFUzUxMiJ9.
                UGF5bG9hZA.
                AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZq
                wqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8Kp
                EHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn
                """
            )
        )
        try jws.validate(key: publicKey)
        #expect(jws.payload == Data("Payload".utf8))
    }

    @Test("Create and validate RSA JWS")
    func createAndValidateRSAJWS() async throws {
        let keys = try makeRSAKeyPair()
        let jws = try JWS.sign(
            header: try JOSEHeader(alg: .RS256),
            payload: "random payload".data(using: .utf8)!,
            key: keys.private
        )
        try jws.validate(key: keys.public)
    }

    @Test("RFC 7515 A.1 HMAC JWS")
    func validateRFCHS256JWS() async throws {
        let jws = try JWS(
            compactSerialization: stripped(
                """
                eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.
                eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt
                cGxlLmNvbS9pc19yb290Ijp0cnVlfQ.
                dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
                """
            )
        )
        let key = JWK(
            kty: .oct,
            k: "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
        ).symmetricKey()!
        try jws.validate(key: key)
        let claims = try JSONDecoder().decode(JWTClaims.self, from: jws.payload)
        #expect(claims.iss == "joe")
        #expect(claims.exp == Date(timeIntervalSince1970: 1_300_819_380))
        #expect(claims["http://example.com/is_root"] as? Bool == true)
    }

    @Test("Reject wrong HMAC key")
    func rejectWrongHMACKey() async throws {
        let jws = try JWS(
            compactSerialization:
                "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        )
        let wrongKey = Data("wrong-secret".utf8)

        do {
            try jws.validate(key: wrongKey)
            #expect(Bool(false))
        } catch let error as JWSError { #expect(error == .hmacVerificationFailed) } catch { #expect(Bool(false)) }
    }

    @Test("Reject unsupported algorithm")
    func rejectUnsupportedAlgorithm() async throws {
        let keys = try makeECKeyPair()
        do {
            _ = try JWS.sign(
                header: try JOSEHeader(alg: .DIR),
                payload: "payload".data(using: .utf8)!,
                key: keys.private
            )
            #expect(Bool(false))
        } catch let error as JWSError { #expect(error == .unsupportedAlgorithm) } catch { #expect(Bool(false)) }
    }

    @Test("Reject invalid compact serialization")
    func rejectInvalidCompactSerialization() async throws {
        do {
            _ = try JWS(compactSerialization: "abc.def")
            #expect(Bool(false))
        } catch let error as JWSError { #expect(error == .invalidJWS) } catch { #expect(Bool(false)) }
    }

    @Test("Reject malformed base64url")
    func rejectMalformedBase64URL() async throws {
        do {
            _ = try JWS(compactSerialization: "!!!!.!!!!.!!!!")
            #expect(Bool(false))
        } catch let error as JWSError { #expect(error == .invalidJWS) } catch { #expect(Bool(false)) }
    }

    @Test("Reject wrong key type for algorithm")
    func rejectWrongKeyTypeForAlgorithm() async throws {
        let ecKeys = try makeECKeyPair()
        let rsaKeys = try makeRSAKeyPair()
        let jws = try JWS.sign(
            header: try JOSEHeader(alg: .ES256),
            payload: "random payload".data(using: .utf8)!,
            key: ecKeys.private
        )

        do {
            try jws.validate(key: rsaKeys.public)
            #expect(Bool(false))
        } catch let error as JWSError { #expect(error == .unsupportedAlgorithm) } catch { #expect(Bool(false)) }
    }
}
