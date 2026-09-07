## 2.0.0

* Breaking: `AuthenticatorInfo.algorithms` now has type
  `List<Map<String, dynamic>>?`, since the `type` member is a string.
* Breaking: COSE keys, including unsupported algorithms, now require integer
  `kty` (1) and `alg` (3). Incomplete unknown keys throw.
* Preserve COSE arrays without byte-list inference; unknown byte strings must
  use `CborBytes`. Wire decoding rejects duplicate CBOR labels.
* Check returned user handles against trusted account bindings and expose
  verified backup state through `authenticateCompleteResult`.
* Reject conflicting initialization options and malformed CTAP field types.
* Move all production cryptography to Rust (native FFI and Web WASM).
* Add SM2 compatibility profiles, RFC 9964 ML-DSA keys, Ed25519 and verification.
* Add configurable WebAuthn ceremonies, strict sequential authenticator CBOR
  parsing, and unknown COSE field roundtrips.
* Require explicit backend initialization and Dart 3.4+; see migration notes.
* Keep full v1 HMAC API results while applying 16-byte MACs to CTAP wire requests.

## 0.0.4

- Fix some CborType related errors by bumping `cbor` to `6.2.0`
- Add more documentation
- Add `ctap2/credmgmt.dart` to export list

## 0.0.3

- Add CredentialManagement support.

## 0.0.2

- Add ClientPin support.
- Add an example that uses PC/SC to communicate with the authenticator.

## 0.0.1

- Initial version.
