//
//  JWETests.swift
//  JOSE
//
//  Created by Biao Luo on 23/04/2026.
//

import Foundation
import Security
import Testing

@testable import JOSE

struct JWETests {
    private func makeRSAKeyPair() -> (private: SecKey, public: SecKey) {
        let privateKey = SecKeyCreateRandomKey(
            [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 2048, kSecAttrIsPermanent: false]
                as NSDictionary,
            nil
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
            nil
        )!
        let publicKey = SecKeyCopyPublicKey(privateKey)!
        return (privateKey, publicKey)
    }

    private func stripped(_ string: String) -> String {
        string.replacingOccurrences(of: "\\s+", with: "", options: .regularExpression)
    }

    @Test("Encrypt and decrypt compact JWE with A128GCM")
    func encryptDecryptA128GCM() async throws {
        let key = Data((0..<16).map { UInt8($0) })
        let header = try JOSEHeader(alg: .DIR, enc: "A128GCM")
        let plaintext = Data("hello apple-native jwe".utf8)

        let jwe = try JWE.encrypt(plaintext: plaintext, key: key, header: header)
        let decrypted = try JWE.decrypt(compactSerialization: jwe.compactSerialization, key: key)

        #expect(decrypted == plaintext)
        #expect(jwe.encryptedKey.isEmpty)
        #expect(jwe.initializationVector.count == 12)
        #expect(jwe.tag.count == 16)
    }

    @Test("Encrypt and decrypt compact JWE with A256GCM")
    func encryptDecryptA256GCM() async throws {
        let key = Data((0..<32).map { UInt8($0) })
        let header = try JOSEHeader(alg: .DIR, enc: "A256GCM")
        let plaintext = Data("hello apple-native jwe".utf8)

        let jwe = try JWE.encrypt(plaintext: plaintext, key: key, header: header)
        let decrypted = try JWE.decrypt(compactSerialization: jwe.compactSerialization, key: key)

        #expect(decrypted == plaintext)
    }

    @Test("Reject invalid compact JWE shape")
    func rejectInvalidShape() async throws {
        do {
            _ = try JWE(compactSerialization: "a.b.c")
            #expect(Bool(false))
        } catch let error as JWEError { #expect(error == .invalidJWE) } catch { #expect(Bool(false)) }
    }

    @Test("Reject wrong direct encryption key length")
    func rejectWrongKeyLength() async throws {
        let key = Data((0..<15).map { UInt8($0) })
        let header = try JOSEHeader(alg: .DIR, enc: "A128GCM")

        do {
            _ = try JWE.encrypt(plaintext: Data("hello".utf8), key: key, header: header)
            #expect(Bool(false))
        } catch let error as JWEError { #expect(error == .invalidKey) } catch { #expect(Bool(false)) }
    }

    @Test("Reject unsupported JWE encryption algorithm")
    func rejectUnsupportedEnc() async throws {
        let key = Data((0..<16).map { UInt8($0) })
        let header = try JOSEHeader(alg: .DIR, enc: "A128CBC-HS256")

        do {
            _ = try JWE.encrypt(plaintext: Data("hello".utf8), key: key, header: header)
            #expect(Bool(false))
        } catch let error as JWEError { #expect(error == .unsupportedAlgorithm) } catch { #expect(Bool(false)) }
    }

    @Test("Reject tampered compact JWE tag")
    func rejectTamperedTag() async throws {
        let key = Data((0..<16).map { UInt8($0) })
        let header = try JOSEHeader(alg: .DIR, enc: "A128GCM")
        let plaintext = Data("hello apple-native jwe".utf8)
        let jwe = try JWE.encrypt(plaintext: plaintext, key: key, header: header)

        let parts = jwe.compactSerialization.components(separatedBy: ".")
        var tagBytes = Data(base64URLEncoded: parts[4])!
        tagBytes[0] ^= 0x01
        let tampered = [parts[0], parts[1], parts[2], parts[3], tagBytes.base64URLEncodedString].joined(separator: ".")

        do {
            _ = try JWE.decrypt(compactSerialization: tampered, key: key)
            #expect(Bool(false))
        } catch let error as JWEError { #expect(error == .invalidTag) } catch { #expect(Bool(false)) }
    }

    @Test("Encrypt and decrypt compact JWE with RSA-OAEP-256")
    func encryptDecryptRSAOAEP256() async throws {
        let keys = makeRSAKeyPair()
        let header = try JOSEHeader(alg: .RSA_OAEP_256, enc: "A256GCM")
        let plaintext = Data("hello rsa jwe".utf8)

        let jwe = try JWE.encrypt(plaintext: plaintext, key: keys.public, header: header)
        let decrypted = try JWE.decrypt(compactSerialization: jwe.compactSerialization, key: keys.private)

        #expect(decrypted == plaintext)
        #expect(jwe.encryptedKey.isEmpty == false)
    }

    @Test("Encrypt and decrypt compact JWE with RSA-OAEP")
    func encryptDecryptRSAOAEP() async throws {
        let keys = makeRSAKeyPair()
        let header = try JOSEHeader(alg: .RSA_OAEP, enc: "A128GCM")
        let plaintext = Data("hello rsa jwe".utf8)

        let jwe = try JWE.encrypt(plaintext: plaintext, key: keys.public, header: header)
        let decrypted = try JWE.decrypt(compactSerialization: jwe.compactSerialization, key: keys.private)

        #expect(decrypted == plaintext)
    }

    @Test("Encrypt and decrypt compact JWE with ECDH-ES")
    func encryptDecryptECDHES() async throws {
        let keys = makeECKeyPair(sizeInBits: 256)
        let header = try JOSEHeader(alg: .ECDH_ES, enc: "A256GCM")
        let plaintext = Data("hello ecdh jwe".utf8)

        let jwe = try JWE.encrypt(plaintext: plaintext, key: keys.public, header: header)
        let parsed = try JWE(compactSerialization: jwe.compactSerialization)
        let decrypted = try JWE.decrypt(compactSerialization: jwe.compactSerialization, key: keys.private)

        #expect(decrypted == plaintext)
        #expect(jwe.encryptedKey.isEmpty)
        #expect(parsed.header.epk != nil)
    }

    @Test("Encrypt and decrypt compact JWE with ECDH-ES+A128KW")
    func encryptDecryptECDHESA128KW() async throws {
        let keys = makeECKeyPair(sizeInBits: 256)
        let header = try JOSEHeader(alg: .ECDH_ES_A128KW, enc: "A128GCM")
        let plaintext = Data("hello ecdh kw jwe".utf8)

        let jwe = try JWE.encrypt(plaintext: plaintext, key: keys.public, header: header)
        let parsed = try JWE(compactSerialization: jwe.compactSerialization)
        let decrypted = try JWE.decrypt(compactSerialization: jwe.compactSerialization, key: keys.private)

        #expect(decrypted == plaintext)
        #expect(jwe.encryptedKey.isEmpty == false)
        #expect(parsed.header.epk != nil)
    }

    @Test("Encrypt and decrypt compact JWE with ECDH-ES+A256KW")
    func encryptDecryptECDHESA256KW() async throws {
        let keys = makeECKeyPair(sizeInBits: 256)
        let header = try JOSEHeader(alg: .ECDH_ES_A256KW, enc: "A256GCM")
        let plaintext = Data("hello ecdh kw jwe".utf8)

        let jwe = try JWE.encrypt(plaintext: plaintext, key: keys.public, header: header)
        let parsed = try JWE(compactSerialization: jwe.compactSerialization)
        let decrypted = try JWE.decrypt(compactSerialization: jwe.compactSerialization, key: keys.private)

        #expect(decrypted == plaintext)
        #expect(jwe.encryptedKey.isEmpty == false)
        #expect(parsed.header.epk != nil)
    }

    @Test("Decrypt RFC 7516 RSA-OAEP example")
    func decryptRFC7516RSAOAEPExample() async throws {
        let privateJWK = JWK.rsa(
            n: stripped(
                """
                oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUW
                cJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3S
                psk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2a
                sbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMS
                tPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2dj
                YgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw
                """
            ),
            e: "AQAB",
            d: stripped(
                """
                kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5N
                WV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD9
                3Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghk
                qDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vl
                t3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSnd
                VTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ
                """
            ),
            p: stripped(
                """
                1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-
                SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAEPTPjXv_hI2_1eTSPVZfzL0lf
                fNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0
                """
            ),
            q: stripped(
                """
                wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBm
                UDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aX
                IWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc
                """
            ),
            dp: stripped(
                """
                ZK-YwE7diUh0qR1tR7w8WHtolDx3MZ_OTowiFvgfeQ3SiresXjm9gZ5KL
                hMXvo-uz-KUJWDxS5pFQ_M0evdo1dKiRTjVw_x4NyqyXPM5nULPkcpU827
                rnpZzAJKpdhWAgqrXGKAECQH0Xt4taznjnd_zVpAmZZq60WPMBMfKcuE
                """
            ),
            dq: stripped(
                """
                Dq0gfgJ1DdFGXiLvQEZnuKEN0UUmsJBxkjydc3j4ZYdBiMRAy86x0vHCj
                ywcMlYYg4yoC4YZa9hNVcsjqA3FeiL19rk8g6Qn29Tt0cj8qqyFpz9vNDB
                UfCAiJVeESOjJDZPYHdHY8v1b-o-Z2X5tvLx-TCekf7oxyeKDUqKWjis
                """
            ),
            qi: stripped(
                """
                VIMpMYbPf47dT1w_zDUXfPimsSegnMOA1zTaX7aGk_8urY6R8-ZW1FxU7
                AlWAyLWybqq6t16VFd7hQd0y6flUK4SlOydB61gwanOsXGOAOv82cHq0E3
                eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9JF_XyaY14ardLSjf4L_FNY
                """
            ),
            alg: .RSA_OAEP,
            use: .enc,
            kid: "2011-04-29"
        )

        let compact = stripped(
            """
            eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.
            OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe
            ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb
            Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV
            mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8
            1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi
            6UklfCpIMfIjf7iGdXKHzg.
            48V1_ALb6US04U3b.
            5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji
            SdiwkIr3ajwQzaBtQD_A.
            XFBoMYUZodetZdvTiFvSkQ
            """
        )

        let jwe = try JWE(compactSerialization: compact)
        #expect(jwe.header.alg == .RSA_OAEP)
        #expect(jwe.header.enc == "A256GCM")
        #expect(
            jwe.encryptedKey.base64URLEncodedString
                == "OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg"
        )
        #expect(jwe.initializationVector.base64URLEncodedString == "48V1_ALb6US04U3b")
        #expect(jwe.tag.base64URLEncodedString == "XFBoMYUZodetZdvTiFvSkQ")

        let plaintext = try JWE.decrypt(compactSerialization: compact, key: privateJWK.privateRSAKey()!)
        #expect(
            String(decoding: plaintext, as: UTF8.self)
                == "The true sign of intelligence is not knowledge but imagination."
        )
    }
}
