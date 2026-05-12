//
//  ConcatKDF.swift
//  JOSE
//
//  Created by Biao Luo on 23/04/2026.
//

import CryptoKit
import Foundation

enum ConcatKDFError: Error, Equatable { case invalidKeyLength }

enum ConcatKDF {
    enum DigestAlgorithm {
        case sha256
        case sha384
        case sha512

        var digestLengthInBytes: Int {
            switch self {
            case .sha256: 32
            case .sha384: 48
            case .sha512: 64
            }
        }
    }

    static func deriveKey(
        z: Data,
        keyDataLengthBits: Int,
        algorithmID: Data,
        partyUInfo: Data? = nil,
        partyVInfo: Data? = nil,
        suppPrivInfo: Data? = nil,
        digestAlgorithm: DigestAlgorithm = .sha256
    ) throws -> Data {
        guard keyDataLengthBits > 0, keyDataLengthBits % 8 == 0 else { throw ConcatKDFError.invalidKeyLength }

        let keyLengthInBytes = keyDataLengthBits / 8
        let otherInfo = Data.concatKDFOtherInfo(
            algorithmID: algorithmID,
            partyUInfo: partyUInfo ?? Data(),
            partyVInfo: partyVInfo ?? Data(),
            keyDataLengthBits: keyDataLengthBits,
            suppPrivInfo: suppPrivInfo
        )

        var result = Data()
        result.reserveCapacity(keyLengthInBytes)

        var counter: UInt32 = 1
        while result.count < keyLengthInBytes {
            var input = Data()
            input.append(contentsOf: counter.bigEndianBytes)
            input.append(z)
            input.append(otherInfo)

            let digest = Self.digest(input, algorithm: digestAlgorithm)
            result.append(digest)
            counter += 1
        }

        return result.prefix(keyLengthInBytes)
    }

    static func deriveKey(
        z: Data,
        keyDataLengthBits: Int,
        algorithmID: String,
        partyUInfo: String? = nil,
        partyVInfo: String? = nil,
        suppPrivInfo: Data? = nil,
        digestAlgorithm: DigestAlgorithm = .sha256
    ) throws -> Data {
        try deriveKey(
            z: z,
            keyDataLengthBits: keyDataLengthBits,
            algorithmID: Data(algorithmID.utf8),
            partyUInfo: partyUInfo.map { Data($0.utf8) },
            partyVInfo: partyVInfo.map { Data($0.utf8) },
            suppPrivInfo: suppPrivInfo,
            digestAlgorithm: digestAlgorithm
        )
    }

    private static func digest(_ data: Data, algorithm: DigestAlgorithm) -> Data {
        switch algorithm {
        case .sha256: return Data(SHA256.hash(data: data))
        case .sha384: return Data(SHA384.hash(data: data))
        case .sha512: return Data(SHA512.hash(data: data))
        }
    }
}

extension Data {
    fileprivate static func concatKDFOtherInfo(
        algorithmID: Data,
        partyUInfo: Data,
        partyVInfo: Data,
        keyDataLengthBits: Int,
        suppPrivInfo: Data?
    ) -> Data {
        var otherInfo = Data()
        otherInfo.append(lengthPrefixed(algorithmID))
        otherInfo.append(lengthPrefixed(partyUInfo))
        otherInfo.append(lengthPrefixed(partyVInfo))
        otherInfo.append(contentsOf: UInt32(keyDataLengthBits).bigEndianBytes)
        if let suppPrivInfo { otherInfo.append(lengthPrefixed(suppPrivInfo)) }
        return otherInfo
    }

    fileprivate static func lengthPrefixed(_ data: Data) -> Data {
        var prefixed = Data()
        prefixed.append(contentsOf: UInt32(data.count).bigEndianBytes)
        prefixed.append(data)
        return prefixed
    }
}

extension UInt32 { fileprivate var bigEndianBytes: [UInt8] { withUnsafeBytes(of: bigEndian, Array.init) } }
