import Foundation
import Testing

@testable import JOSE

struct SignedDescriptionTests {
    @Test("Signed.description includes header and payload JSON")
    func signedDescription() async throws {
        let claims = JWTClaims(
            iss: "https://auth.example.com",
            sub: "user_123",
            aud: "myapp",
            privateClaims: ["role": "admin"]
        )
        let header = try JOSEHeader(alg: .HS256, typ: "JWT")
        let key = Data("super-secret-key".utf8)

        let signed = try JWT.sign(header: header, claims: claims, key: key)
        let desc = signed.description

        let expected = """
            {
              "header" : {
                "alg" : "HS256",
                "typ" : "JWT"
              },
              "payload" : {
                "aud" : "myapp",
                "iss" : "https:\\/\\/auth.example.com",
                "role" : "admin",
                "sub" : "user_123"
              }
            }
            """

        #expect(desc == expected)
    }
}
