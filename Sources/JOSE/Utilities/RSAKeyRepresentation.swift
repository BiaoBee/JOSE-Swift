//
//  RSAKeyRepresentation.swift
//  JOSE
//
//  Created by Biao Luo on 19/04/2026.
//

import Foundation

enum RSAKeyRepresentation {
    static func publicComponents(from externalRepresentation: Data) -> (n: Data, e: Data)? {
        var reader = DERReader(data: externalRepresentation)
        guard let sequence = reader.readSequence(), reader.isAtEnd else { return nil }
        var innerReader = DERReader(data: sequence)
        guard let inner = innerReader.readIntegers(count: 2), inner.count == 2 else { return nil }
        return (n: normalizePositiveInteger(inner[0]), e: normalizePositiveInteger(inner[1]))
    }

    static func privateComponents(
        from externalRepresentation: Data
    ) -> (n: Data, e: Data, d: Data, p: Data, q: Data, dp: Data, dq: Data, qi: Data)? {
        var reader = DERReader(data: externalRepresentation)
        guard let sequence = reader.readSequence(), reader.isAtEnd else { return nil }

        var inner = DERReader(data: sequence)
        guard inner.readInteger() != nil,  // version
            let integers = inner.readIntegers(count: 8), integers.count == 8, inner.isAtEnd
        else { return nil }

        return (
            n: normalizePositiveInteger(integers[0]), e: normalizePositiveInteger(integers[1]),
            d: normalizePositiveInteger(integers[2]), p: normalizePositiveInteger(integers[3]),
            q: normalizePositiveInteger(integers[4]), dp: normalizePositiveInteger(integers[5]),
            dq: normalizePositiveInteger(integers[6]), qi: normalizePositiveInteger(integers[7])
        )
    }

    static func publicKeyData(modulus n: Data, exponent e: Data) -> Data {
        encodeSequence([encodeInteger(n), encodeInteger(e)])
    }

    static func privateKeyData(n: Data, e: Data, d: Data, p: Data, q: Data, dp: Data, dq: Data, qi: Data) -> Data {
        let version = encodeInteger(Data([0x00]))
        return encodeSequence([
            version, encodeInteger(n), encodeInteger(e), encodeInteger(d), encodeInteger(p), encodeInteger(q),
            encodeInteger(dp), encodeInteger(dq), encodeInteger(qi),
        ])
    }

    static func keySizeInBits(from modulus: Data) -> Int {
        guard let firstByte = modulus.first else { return 0 }
        let leadingZeroBits = firstByte.leadingZeroBitCount
        return (modulus.count * 8) - leadingZeroBits
    }

    private static func normalizePositiveInteger(_ data: Data) -> Data {
        let stripped = Data(data.drop(while: { $0 == 0x00 }))
        return stripped.isEmpty ? Data([0x00]) : stripped
    }

    private static func encodeInteger(_ value: Data) -> Data {
        let normalized = normalizePositiveInteger(value)
        let needsLeadingZero = normalized.first.map { $0 & 0x80 != 0 } ?? false
        let integerBytes = needsLeadingZero ? Data([0x00]) + normalized : normalized
        return Data([0x02]) + encodeLength(integerBytes.count) + integerBytes
    }

    private static func encodeSequence(_ elements: [Data]) -> Data {
        let body = elements.reduce(into: Data()) { partialResult, element in partialResult.append(element) }
        return Data([0x30]) + encodeLength(body.count) + body
    }

    private static func encodeLength(_ length: Int) -> Data {
        if length < 0x80 { return Data([UInt8(length)]) }

        var length = length
        var bytes: [UInt8] = []
        while length > 0 {
            bytes.insert(UInt8(length & 0xFF), at: 0)
            length >>= 8
        }
        return Data([0x80 | UInt8(bytes.count)] + bytes)
    }
}

struct DERReader {
    let data: Data
    private var offset: Int = 0

    init(data: Data) { self.data = data }

    var isAtEnd: Bool { offset >= data.count }

    mutating func readSequence() -> Data? {
        guard readByte() == 0x30, let length = readLength(), let bytes = readBytes(length) else { return nil }
        return bytes
    }

    mutating func readInteger() -> Data? {
        guard readByte() == 0x02, let length = readLength(), let bytes = readBytes(length) else { return nil }
        return bytes
    }

    mutating func readIntegers(count: Int) -> [Data]? {
        var values: [Data] = []
        values.reserveCapacity(count)
        for _ in 0..<count {
            guard let value = readInteger() else { return nil }
            values.append(value)
        }
        return values
    }

    private mutating func readByte() -> UInt8? {
        guard offset < data.count else { return nil }
        defer { offset += 1 }
        return data[offset]
    }

    private mutating func readLength() -> Int? {
        guard let firstByte = readByte() else { return nil }
        if firstByte & 0x80 == 0 { return Int(firstByte) }

        let count = Int(firstByte & 0x7F)
        guard count > 0, let bytes = readBytes(count) else { return nil }

        return bytes.reduce(into: 0) { partialResult, byte in partialResult = (partialResult << 8) | Int(byte) }
    }

    private mutating func readBytes(_ count: Int) -> Data? {
        guard count >= 0, offset + count <= data.count else { return nil }
        let slice = data[offset..<(offset + count)]
        offset += count
        return Data(slice)
    }
}
