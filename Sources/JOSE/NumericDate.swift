//
//  NumericDate.swift
//  JOSE
//
//  Created by Biao Luo on 06/07/2025.
//

import Foundation

struct NumericDate: Codable {
    let value: Int64
    
    var date: Date {
        Date(timeIntervalSince1970: TimeInterval(value))
    }
    
    init?(date: Date?) {
        guard let date else {
            return nil
        }
        self.value = Int64(date.timeIntervalSince1970)
    }
    
    enum CodingKeys: CodingKey {
        case value
    }
    
    func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(value)
    }
    
    init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        self.value = try container.decode(Int64.self)
    }
}
