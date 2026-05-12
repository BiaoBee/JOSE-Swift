//
//  ConcatKDFTests.swift
//  JOSETests
//
//  Created by Biao Luo on 23/04/2026.
//

import Foundation
import Testing

@testable import JOSE

struct ConcatKDFTests {
    @Test("RFC 7518 Appendix C Concat KDF")
    func deriveRFC7518Example() throws {
        let z = Data([
            158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49, 110, 163, 218, 128, 106,
            72, 246, 218, 167, 121, 140, 254, 144, 196,
        ])

        let derivedKey = try ConcatKDF.deriveKey(
            z: z,
            keyDataLengthBits: 128,
            algorithmID: "A128GCM",
            partyUInfo: "Alice",
            partyVInfo: "Bob"
        )

        #expect(derivedKey.base64URLEncodedString == "VqqN6vgjbSBcIijNcacQGg")
    }
}
