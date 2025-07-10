//
//  JOSEHeaderTests.swift
//  JOSE
//
//  Created by Biao Luo on 10/07/2025.
//

import Testing
import Foundation
@testable import JOSE

struct Test {
    @Test("Decode JOSE Header - JWS with certificate chain") func decodeJWSWithCertChain() async throws {
        let headerData = """
            {
              "alg": "ES256",
              "kid": "123",
              "x5c": [
                "CERT1",
                "CERT2"
              ]
            }
            """.data(using: .utf8)!
        let header = try JSONDecoder().decode(JOSEHeader.self, from: headerData)
        #expect(header.alg == .ES256)
        #expect(header.kid == "123")
        #expect(header.x5c == ["CERT1", "CERT2"])
    }
    
    @Test("Decode JOSE header - JWS with JWK") func decodeJWSWithJWK() async throws {
        let headerData = """
            {
              "alg": "ES256",
              "jwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": "x",
                "y": "y",
                "kid": "kid"
              }
            }
            """.data(using: .utf8)!
        let header = try JSONDecoder().decode(JOSEHeader.self, from: headerData)
        #expect(header.alg == .ES256)
        #expect(header.jwk == JWK.ec(crv: .P256, x: "x", y: "y", kid: "kid"))
    }
}
