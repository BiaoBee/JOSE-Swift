//
//  JOSEHeaderTests.swift
//  JOSE
//
//  Created by Biao Luo on 10/07/2025.
//

import Foundation
import Testing

@testable import JOSE

struct Test {
    @Test("Decode JOSE Header - JWS with certificate chain")
    func decodeJWSWithCertChain() async throws {
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

    @Test("Decode JOSE header - JWS with JWK")
    func decodeJWSWithJWK() async throws {
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

    @Test("Decode JOSE header preserves custom parameters")
    func decodeHeaderWithCustomParameters() async throws {
        let headerData = """
            {
              "alg": "RS256",
              "kid": "123",
              "tenant": "internal",
              "features": ["a", "b"]
            }
            """.data(using: .utf8)!
        let header = try JSONDecoder().decode(JOSEHeader.self, from: headerData)

        #expect(header.alg == .RS256)
        #expect(header.kid == "123")
        #expect(header.customParameters["tenant"] as? String == "internal")
        #expect(header.customParameters["features"] as? [String] == ["a", "b"])
    }

    @Test("JOSE header custom parameters round-trip")
    func roundTripHeaderWithCustomParameters() async throws {
        let header = try JOSEHeader(alg: .RS256, kid: "123", customParameters: ["tenant": "internal", "enabled": true])

        let data = try JSONEncoder().encode(header)
        let decoded = try JSONDecoder().decode(JOSEHeader.self, from: data)

        #expect(decoded == header)
        #expect(decoded.customParameters["tenant"] as? String == "internal")
        #expect(decoded.customParameters["enabled"] as? Bool == true)
    }

    @Test("Reject custom parameter collision with registered name")
    func rejectCustomParameterCollision() async throws {
        do {
            _ = try JOSEHeader(alg: .RS256, customParameters: ["alg": "HS256"])
            #expect(Bool(false))
        } catch let error as JOSEHeaderError { #expect(error == .customParameterNameCollision("alg")) } catch {
            #expect(Bool(false))
        }
    }

    @Test("Reject duplicate critical parameter")
    func rejectDuplicateCriticalParameter() async throws {
        do {
            _ = try JOSEHeader(alg: .RS256, crit: ["tenant", "tenant"], customParameters: ["tenant": "internal"])
            #expect(Bool(false))
        } catch let error as JOSEHeaderError { #expect(error == .duplicateCriticalParameter("tenant")) } catch {
            #expect(Bool(false))
        }
    }

    @Test("Reject missing critical parameter")
    func rejectMissingCriticalParameter() async throws {
        do {
            _ = try JOSEHeader(alg: .RS256, crit: ["tenant"])
            #expect(Bool(false))
        } catch let error as JOSEHeaderError { #expect(error == .missingCriticalParameter("tenant")) } catch {
            #expect(Bool(false))
        }
    }

    @Test("Reject registered critical parameter")
    func rejectRegisteredCriticalParameter() async throws {
        do {
            _ = try JOSEHeader(alg: .RS256, crit: ["alg"])
            #expect(Bool(false))
        } catch let error as JOSEHeaderError { #expect(error == .invalidCriticalParameter("alg")) } catch {
            #expect(Bool(false))
        }
    }
}
