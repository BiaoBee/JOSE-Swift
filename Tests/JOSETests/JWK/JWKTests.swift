//
//  JWKTests.swift
//  JOSE
//
//  Created by Biao Luo on 19/04/2026.
//

import Foundation
import Security
import Testing

@testable import JOSE

struct JWKTests {
    private func makeRSAKeyPair() -> (private: SecKey, public: SecKey) {
        let privateKey = SecKeyCreateRandomKey(
            [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 2048, kSecAttrIsPermanent: false]
                as NSDictionary,
            nil
        )!
        let publicKey = SecKeyCopyPublicKey(privateKey)!
        return (privateKey, publicKey)
    }

    private func externalRepresentation(of key: SecKey) -> Data {
        var error: Unmanaged<CFError>?
        let data = SecKeyCopyExternalRepresentation(key, &error)
        guard let data else {
            if let error { _ = error.takeRetainedValue() }
            fatalError("Failed to export key representation")
        }
        return data as Data
    }

    @Test("Encode and decode RSA JWK")
    func encodeDecodeRSAJWK() async throws {
        let keys = makeRSAKeyPair()
        let jwk = JWK.rsa(privateKey: keys.private, alg: .RS256, use: .sig, kid: "rsa-key")!
        let encoded = try JSONEncoder().encode(jwk)
        let decoded = try JSONDecoder().decode(JWK.self, from: encoded)

        #expect(decoded == jwk)
        #expect(decoded.kty == .RSA)
        #expect(decoded.alg == .RS256)
        #expect(decoded.use == .sig)
        #expect(decoded.kid == "rsa-key")
        #expect(decoded.publicRSAKey() != nil)
        #expect(decoded.privateRSAKey() != nil)
    }

    @Test("Round trip RSA JWK to SecKey")
    func roundTripRSAJWKToSecKey() async throws {
        let keys = makeRSAKeyPair()
        let publicJWK = JWK.rsa(publicKey: keys.public)!
        let privateJWK = JWK.rsa(privateKey: keys.private)!

        let reconstructedPublic = publicJWK.publicRSAKey()!
        let reconstructedPrivate = privateJWK.privateRSAKey()!

        #expect(externalRepresentation(of: reconstructedPublic) == externalRepresentation(of: keys.public))
        #expect(externalRepresentation(of: reconstructedPrivate) == externalRepresentation(of: keys.private))

        let payload = "rsa-jwk-roundtrip".data(using: .utf8)!
        let jws = try JWS.sign(header: try JOSEHeader(alg: .RS256), payload: payload, key: reconstructedPrivate)
        try jws.validate(key: reconstructedPublic)
    }
}
