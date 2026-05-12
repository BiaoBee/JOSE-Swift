# JOSE Plan

## Goal

Shape the package around a clear public product: JWT workflows first, with `JWT.swift` as the main application-facing API for both signed and encrypted tokens.

## Current Direction

- The README now documents `JWT` and `JWTClaims` as the intended public surface.
- Lower-level JOSE types currently exist in the package, but they should be treated as implementation detail unless they are intentionally promoted.
- The next work should make the codebase match that product boundary more clearly, especially by bringing encrypted token workflows into `JWT.swift`.

## Recently Completed

Completed the TODOs in [Sources/JOSE/Models/JOSEHeader.swift](/Users/luobiao/Documents/GitHub/JOSE-Swift/Sources/JOSE/Models/JOSEHeader.swift):

- added support for custom header parameters
- added validation for the `crit` header parameter

This clears the most explicit unfinished source-level TODOs and makes the header model a better foundation for the next stage.

## Immediate Next Task

Integrate JWE into [JWT.swift](/Users/luobiao/Documents/GitHub/JOSE-Swift/Sources/JOSE/JWT/JWT.swift).

Why this next:

- The README already frames `JWT` as the main public surface.
- Encrypted token workflows should be available through `JWT.swift`, not primarily through lower-level `JWE` APIs.
- It aligns the product story with the code structure you want to grow toward.

## Near-Term Priorities

### 1. Integrate JWE into `JWT.swift`

- Design a JWT-level API for encrypted tokens instead of exposing JWE as the primary workflow.
- Decide how encrypted JWTs should be created, parsed, decrypted, and validated from the `JWT` namespace.
- Keep the public API consistent with the existing signed JWT flow where possible.
- Update documentation only through the JWT-level API once this lands.

### 2. Define the public API boundary

- Decide which types are truly public in the long term.
- Keep `JWT` and `JWTClaims` as the primary supported surface for now.
- Review whether `JWS`, `JWE`, `JWK`, `JOSEHeader`, and utility types should stay public, become internal, or move behind a more deliberate API.

### 3. Improve JWT validation

- Add JWT-level claim validation helpers in addition to signature validation.
- Cover common checks such as:
  - expiration (`exp`)
  - not-before (`nbf`)
  - issuer (`iss`)
  - audience (`aud`)
- Keep the API small and explicit so application code can adopt it easily.

### 4. Align tests with the product story

- Keep strong lower-level tests for internal correctness.
- Add or expand tests around the JWT facade so the intended public workflow is fully covered.
- Reduce reliance on deprecated names such as `CompactJWS` in tests where practical.

### 5. Clean up public naming

- Review names that expose lower-level implementation details too early.
- Prefer naming that reflects the package’s supported user workflow instead of its internal layering.
- Remove or de-emphasize deprecated aliases once downstream-facing API decisions are settled.

## Success Criteria

- `JOSEHeader` can represent standard and custom JOSE header parameters correctly.
- Critical header validation is explicit and tested.
- Encrypted token workflows are exposed through `JWT.swift`.
- The package presents a clear JWT-first public story.
- The README and code agree on what is public and supported.
- Common JWT workflows are ergonomic:
  - create
  - parse
  - validate signature or decrypt
  - validate claims
- JWE support is introduced only through a deliberate JWT-level API.
