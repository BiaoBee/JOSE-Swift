//
//  StringCodingKey.swift
//  JOSE
//
//  Created by Biao Luo on 08/07/2025.
//

import Foundation

struct StringCodingKey: CodingKey {
    var stringValue: String
    
    init?(stringValue: String) {
        self.stringValue = stringValue
    }
    
    var intValue: Int? = nil
    
    init?(intValue: Int) {
        nil
    }
}
