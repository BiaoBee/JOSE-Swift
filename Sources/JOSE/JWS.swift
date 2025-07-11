//
//  JWS.swift
//  JOSE
//
//  Created by Biao Luo on 04/07/2025.
//

import Foundation

public struct CompactJWS: Equatable {
    public let header: JOSEHeader
    public let payload: Data
    public let signature: Data
    
    init(header: JOSEHeader, payload: Data, signature: Data) {
        self.header = header
        self.payload = payload
        self.signature = signature
    }
    
    public func compactSerialization() throws -> String {
        let protectedHeader = try JSONEncoder().encode(header)
        let base64URLHeader = protectedHeader.base64URLEncodedString
        let base64URLPayload = payload.base64URLEncodedString
        let base64URLSignature = signature.base64URLEncodedString
        return "\(base64URLHeader).\(base64URLPayload).\(base64URLSignature)"
    }
    
    public init?(compactSerialization: String) {
        let components = compactSerialization.components(separatedBy: ".")
        guard components.count == 3 else {
            return nil
        }
        
        guard let headerData = Data(base64URLEncodedString: components[0]),
              let header = try? JSONDecoder().decode(JOSEHeader.self, from: headerData),
              let payload = Data(base64URLEncodedString: components[1]),
              let signature = Data(base64URLEncodedString: components[2]) else {
            return nil
        }
        self.header = header
        self.payload = payload
        self.signature = signature
    }
}

extension CompactJWS {
    static func create(key: SecKey, alg: JWA, header: JOSEHeader, payload: Data) throws -> CompactJWS {
        var header = header
        header.alg = alg
        
        let protectedHeader = try JSONEncoder().encode(header)
        let base64URLHeader = protectedHeader.base64URLEncodedString
        let base64URLPayload = payload.base64URLEncodedString
        let toBeSigned = "\(base64URLHeader).\(base64URLPayload)".data(using: .ascii) ?? Data()
        let signature = try Crypto.sign(data: toBeSigned, key: key, alg: alg)
        return CompactJWS(header: header, payload: payload, signature: signature)
    }
}

// TODO: JSON JWS
