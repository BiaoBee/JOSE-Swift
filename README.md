# JOSE

[![Swift 6.0+](https://img.shields.io/badge/Swift-6.0%2B-F05138.svg)](https://swift.org)
[![Platforms](https://img.shields.io/badge/Platforms-iOS%2013%2B%20%7C%20macOS%2011%2B%20%7C%20tvOS%2013%2B%20%7C%20watchOS%206%2B-0A84FF.svg)](https://github.com/BiaoBee/JOSE-Swift)
[![Release](https://img.shields.io/github/v/release/BiaoBee/JOSE-Swift)](https://github.com/BiaoBee/JOSE-Swift/releases)
[![License](https://img.shields.io/github/license/BiaoBee/JOSE-Swift)](https://github.com/BiaoBee/JOSE-Swift/blob/main/LICENSE.md)

Swift package for working with JOSE standards on Apple platforms, including signing, verification, encryption, decryption, and JWT claims handling.

## Overview

- JWT signing and verification for HMAC, RSA, and ECDSA algorithms
- JWT encryption and decryption for direct, RSA, and ECDH-based JWE flows
- Token-oriented API built around `JWT`, `JWT.Signed`, and `JWT.Encrypted`
- Apple-platform implementation using `Foundation`, `Security`, and `CryptoKit`

## Contents

- [Public JWT API](#public-jwt-api)
- [Requirements](#requirements)
- [Installation](#installation)
- [Supported JWT Signing Algorithms](#supported-jwt-signing-algorithms)
- [Supported JWT Encryption Algorithms](#supported-jwt-encryption-algorithms)
- [JWT Claims](#jwt-claims)
- [Signing JWTs With HMAC](#signing-jwts-with-hmac)
- [Signing JWTs With Asymmetric Keys](#signing-jwts-with-asymmetric-keys)
- [Parsing Existing Tokens](#parsing-existing-tokens)
- [Encrypting JWTs](#encrypting-jwts)

JOSE is a Swift package for creating, parsing, validating, encrypting, and decrypting JWTs on Apple platforms.

The package is now available as `1.0.0`. Review the API and security properties carefully before adopting it in production security-critical workloads.

## Public JWT API

- `JWTClaims` models registered JWT claims and custom private claims.
- `JWT.sign(header:claims:key:)` creates a signed JWT.
- `JWT.Signed` parses an existing signed JWT.
- `JWT.Signed.validate(...)` verifies the JWT signature.
- `JWT.encrypt(header:claims:key:)` creates an encrypted JWT.
- `JWT.Encrypted` parses an existing encrypted JWT header without decrypting it.
- `JWT.Encrypted.decryptData(...)` and `decryptClaims(...)` decrypt the payload.

`JWT`, `JWT.Signed`, and `JWT.Encrypted` are the intended token-facing API for application code.

## Requirements

- Swift 6.0 or later
- iOS 13+
- macOS 11+
- tvOS 13+
- watchOS 6+

The implementation uses `Foundation`, `Security`, and `CryptoKit`, with `AnyCodable` used to preserve arbitrary JWT private claims.

## Installation

Add the package to your `Package.swift`:

```swift
.package(url: "https://github.com/BiaoBee/JOSE-Swift", from: "1.0.0")
```

Then add the `JOSE` product to your target:

```swift
.product(name: "JOSE", package: "JOSE-Swift")
```

## Supported JWT Signing Algorithms

- HMAC: `HS256`, `HS384`, `HS512`
- ECDSA: `ES256`, `ES384`, `ES512`
- RSA: `RS256`, `RS384`, `RS512`

Use a `Data` key for HMAC algorithms and a `SecKey` for ECDSA or RSA algorithms.

## Supported JWT Encryption Algorithms

- Direct symmetric encryption: `dir`
- RSA key management: `RSA-OAEP`, `RSA-OAEP-256`
- ECDH key management: `ECDH-ES`, `ECDH-ES+A128KW`, `ECDH-ES+A256KW`

Use a `Data` key for direct encryption and a `SecKey` for RSA or ECDH key management.

## JWT Claims

`JWTClaims` models standard claims plus `privateClaims`. Dates are encoded as JWT NumericDate values.

```swift
import Foundation
import JOSE

let claims = JWTClaims(
    iss: "https://auth.example.com",
    sub: "user_123",
    aud: "myapp",
    exp: Date(timeIntervalSince1970: 1_752_109_200),
    iat: Date(timeIntervalSince1970: 1_752_105_600),
    privateClaims: [
        "role": "admin",
        "feature_flags": ["beta": true]
    ]
)

let data = try JSONEncoder().encode(claims)
let decoded = try JSONDecoder().decode(JWTClaims.self, from: data)
```

Registered claims:

- `iss`: issuer
- `sub`: subject
- `aud`: audience
- `jti`: JWT ID
- `exp`: expiration time
- `nbf`: not-before time
- `iat`: issued-at time

Other JSON fields are stored in `privateClaims`. You can also use the subscript API:

```swift
let role = claims["role"]
```

## Signing JWTs With HMAC

Use HMAC when the signer and verifier share the same secret.

```swift
import Foundation
import JOSE

let claims = JWTClaims(
    iss: "https://auth.example.com",
    sub: "user_123",
    aud: "myapp",
    exp: Date(timeIntervalSince1970: 1_752_109_200),
    iat: Date(timeIntervalSince1970: 1_752_105_600),
    privateClaims: ["role": "admin"]
)

let header = try JOSEHeader(alg: .HS256, typ: "JWT")
let sharedSecret = Data("super-secret-key".utf8)

let signed = try JWT.sign(header: header, claims: claims, key: sharedSecret)
let token = signed.token

let parsed = try JWT.Signed(token)
try parsed.validate(key: sharedSecret)
```

Use a high-entropy secret in real applications.

## Signing JWTs With Asymmetric Keys

Use RSA or ECDSA when a private key signs and other parties verify with the corresponding public key.

RSA example with `RS256`:

```swift
import Foundation
import Security
import JOSE

let privateKey = SecKeyCreateRandomKey(
    [
        kSecAttrKeyType: kSecAttrKeyTypeRSA,
        kSecAttrKeySizeInBits: 2048,
        kSecAttrIsPermanent: false
    ] as NSDictionary,
    nil
)!
let publicKey = SecKeyCopyPublicKey(privateKey)!

let claims = JWTClaims(
    iss: "https://auth.example.com",
    sub: "user_123",
    aud: "myapp",
    exp: Date(timeIntervalSince1970: 1_752_109_200)
)

let header = try JOSEHeader(alg: .RS256, typ: "JWT")
let signed = try JWT.sign(header: header, claims: claims, key: privateKey)

let parsed = try JWT.Signed(signed.token)
try parsed.validate(key: publicKey)
```

ECDSA example with a P-256 key and `ES256`:

```swift
import Foundation
import Security
import JOSE

let privateKey = SecKeyCreateRandomKey(
    [
        kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits: 256,
        kSecAttrIsPermanent: false
    ] as NSDictionary,
    nil
)!
let publicKey = SecKeyCopyPublicKey(privateKey)!

let claims = JWTClaims(
    sub: "user_123",
    exp: Date(timeIntervalSince1970: 1_752_109_200)
)

let header = try JOSEHeader(alg: .ES256, typ: "JWT")
let signed = try JWT.sign(header: header, claims: claims, key: privateKey)

let parsed = try JWT.Signed(signed.token)
try parsed.validate(key: publicKey)
```

## Parsing Existing Tokens

Use `JWT.Signed` to parse a signed token, validate its signature, and then validate the claims your application depends on.

```swift
let parsed = try JWT.Signed(token)
let claims = try parsed.requireClaims()

let subject = claims.sub
let issuer = claims.iss
let role = claims["role"]
```

`JWT.Signed.description` returns a pretty-printed JSON representation of the header and payload.

```swift
print(parsed)
```

Use `JWT.Encrypted` to inspect the protected header before decrypting the payload.

```swift
let parsed = try JWT.Encrypted(token)

let algorithm = parsed.header.alg
let contentEncryption = parsed.header.enc
```

## Encrypting JWTs

Use encrypted JWTs when the claims themselves must remain confidential.

Direct encryption example with `alg = dir` and `A256GCM`:

```swift
import Foundation
import JOSE

let claims = JWTClaims(
    iss: "https://auth.example.com",
    sub: "user_123",
    aud: "myapp",
    exp: Date(timeIntervalSince1970: 1_752_109_200),
    iat: Date(timeIntervalSince1970: 1_752_105_600),
    privateClaims: ["role": "admin"]
)

let header = try JOSEHeader(alg: .DIR, typ: "JWT", enc: "A256GCM")
let key = Data((0..<32).map(UInt8.init))

let encrypted = try JWT.encrypt(header: header, claims: claims, key: key)
let token = encrypted.token

let parsed = try JWT.Encrypted(token)
let decryptedClaims = try parsed.decryptClaims(key: key)
let rawPayload = try parsed.decryptData(key: key)
```

RSA key management example:

```swift
import Foundation
import Security
import JOSE

let privateKey = SecKeyCreateRandomKey(
    [
        kSecAttrKeyType: kSecAttrKeyTypeRSA,
        kSecAttrKeySizeInBits: 2048,
        kSecAttrIsPermanent: false
    ] as NSDictionary,
    nil
)!
let publicKey = SecKeyCopyPublicKey(privateKey)!

let claims = JWTClaims(sub: "user_123")
let header = try JOSEHeader(alg: .RSA_OAEP_256, typ: "JWT", enc: "A256GCM")

let encrypted = try JWT.encrypt(header: header, claims: claims, key: publicKey)
let parsed = try JWT.Encrypted(encrypted.token)
let decryptedClaims = try parsed.decryptClaims(key: privateKey)
```

If the decrypted payload is text rather than claims JSON, decode the `Data` yourself:

```swift
let decryptedData = try parsed.decryptData(key: key)
let plainText = String(data: decryptedData, encoding: .utf8)
```

## Validation Notes

`validate` verifies the signature. Applications should still validate header fields and claim semantics that are specific to their trust boundary, such as:

- `exp`: reject expired tokens
- `nbf`: reject tokens used too early
- `iss`: require the expected issuer
- `aud`: require the expected audience
- `sub`: map the subject to an application identity
- `alg`, `kid`, `typ`, `cty`, and critical headers: require the values your application expects before trusting the token

## Project Structure

- `Sources/JOSE/JWT/JWT.swift`: JWT signing, parsing, and signature validation facade
- `Sources/JOSE/JWT/JWTClaims.swift`: registered and private claim modeling
- `Tests/JOSETests/JWT`: JWT behavior tests

## Verification

Run the test suite with:

```bash
swift test
```

## License

See [`LICENSE.md`](LICENSE.md).
