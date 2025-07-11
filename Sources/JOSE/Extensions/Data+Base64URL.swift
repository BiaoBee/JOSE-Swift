//
//  Data+Base64URL.swift
//  JOSE
//
//  Created by Biao Luo on 10/07/2025.
//

import Foundation

extension Data {
    var base64URLEncodedString: String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    init?(base64URLEncodedString: String) {
        let base64String = base64URLEncodedString.base64URLToBase64()
        self.init(base64Encoded: base64String)
    }
}

extension String {
    func base64URLToBase64() -> String {
        var base64 = self
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        // Add mising paddings.
        let paddingLength = 4 - (base64.count % 4)
        if paddingLength < 4 {
            base64 += String(repeating: "=", count: paddingLength)
        }
        return base64
    }
}
