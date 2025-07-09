🚧 This package is under active development. The API is not stable and may change without warning.

Do not use in production until version 1.0.0 is released.

# JOSE

A Swift implementation of JOSE (Javascript Object Signing and Encryption) standards, including JWT, JWS, JWE, JWK, and related structures. This package is designed for working with JSON Web Tokens and cryptographic keys in a type-safe and standards-compliant way.

## Features

- **JWT Claims**: Standard and custom claims, with support for IANA-registered fields.
- **JOSE Header**: Supports all header parameters from [RFC 7515 (JWS)](https://datatracker.ietf.org/doc/html/rfc7515) and [RFC 7516 (JWE)](https://datatracker.ietf.org/doc/html/rfc7516).
- **JWK**: JSON Web Key support for EC, OKP, and symmetric keys, with extensible enums for key types and curves.
- **JWA**: Enum for supported algorithms as per [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518).
- Codable and type-safe Swift APIs.

## Installation

