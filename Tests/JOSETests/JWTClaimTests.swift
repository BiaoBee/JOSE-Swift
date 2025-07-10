//
//  JWTClaimTests.swift
//
//
//  Created by Biao Luo on 08/07/2025.
//

import Foundation
import Testing
@testable import JOSE

struct JWTClaimTests {
    @Test("Decoding public JWT claims") func decode() async throws {
        let basicClaims = """
            {
              "iss": "https://auth.example.com",
              "sub": "user_123456",
              "aud": "myapp-client-id",
              "exp": 1752109200,
              "nbf": 1752105600,
              "iat": 1752105600,
              "jti": "a1b2c3d4e5f6"
            }
            """.data(using: .utf8)!
        let claims = try JSONDecoder().decode(JWTClaims.self, from: basicClaims)
        #expect(claims.iss == "https://auth.example.com")
        #expect(claims.aud == "myapp-client-id")
        #expect(claims.sub == "user_123456")
        #expect(claims.exp == Date(timeIntervalSince1970: 1752109200))
        #expect(claims.nbf == Date(timeIntervalSince1970: 1752105600))
        #expect(claims.iat == Date(timeIntervalSince1970: 1752105600))
        #expect(claims.jti == "a1b2c3d4e5f6")
    }
    
    @Test("Decode private JWT claims") func decodeWithParivateClaims() async throws {
        let claimsData = """
            {
              "iss": "https://auth.example.com",
              "sub": "user_98765",
              "aud": "your-app-client-id",
              "exp": 1752109200,
              "iat": 1752105600,
              "role": "admin",
              "email": "jane.doe@example.com",
              "name": "Jane Doe",
              "groups": ["admin", "engineering"],
              "feature_flags": {
                "beta_access": true,
                "dark_mode": false
              }
            }
            """.data(using: .utf8)!
        let claims = try JSONDecoder().decode(JWTClaims.self, from: claimsData)
        #expect(claims.iss == "https://auth.example.com")
        #expect(claims.aud == "your-app-client-id")
        #expect(claims.sub == "user_98765")
        #expect(claims.exp == Date(timeIntervalSince1970: 1752109200))
        #expect(claims.nbf == nil)
        #expect(claims.iat == Date(timeIntervalSince1970: 1752105600))
        #expect(claims.jti == nil)
        #expect(claims["name"] as! String == "Jane Doe")
        #expect(claims["groups"] as! [String] == ["admin", "engineering"])
        #expect(claims["feature_flags"] as! [String: Bool] == ["beta_access": true, "dark_mode": false])
    }
    
    @Test("Encode JWT") func encode() async throws {
        let date = Date.now
        let claims = JWTClaims(iss: "iss",
                               sub: "sub",
                               aud: "aud",
                               exp: date,
                               nbf: date,
                               iat: date,
                               privateClaims: [
                                "custom1" : "value1",
                                "custom2" : "value2"
                               ])
        let encodedData = try JSONEncoder().encode(claims)
        let decodedClaims = try JSONSerialization.jsonObject(with: encodedData)
        let numericDate = Int(date.timeIntervalSince1970)
        #expect(decodedClaims as! NSDictionary == [
            "iss": "iss",
            "sub": "sub",
            "aud": "aud",
            "exp": numericDate,
            "nbf": numericDate,
            "iat": numericDate,
            "custom1" : "value1",
            "custom2" : "value2"
        ])
    }
    
    @Test("Claims description") func description() async throws {
        let date = Date.now
        let claims = JWTClaims(iss: "iss",
                               sub: "sub",
                               aud: "aud",
                               exp: date,
                               nbf: date,
                               iat: date,
                               privateClaims: [
                                "custom1" : "value1",
                                "custom2" : "value2"
                               ])
        let description = claims.description
        let jsonPresentation = try String(data: JSONEncoder().encode(claims), encoding: .utf8)!
        #expect(description == jsonPresentation)
    }
}
