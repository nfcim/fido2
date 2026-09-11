## 2.0.1

* Verify packed certificate and self attestation through both registration APIs.
  Add configurable conveyance/accepted formats, immutable attestation evidence
  and an optional synchronous application trust policy. Validate ES256/Ed25519
  leaf certificate profiles in the shared Rust native/WASM backend; certificate
  chain trust remains application-owned. Default accepted formats are none/packed.
* Rebuild the native/Web Rust backend to enable packed certificate validation.

## 2.0.0

* Add `supportedSignatureAlgorithms()`; `supportedAlgorithms()` includes
  ECDH-ES+HKDF-256 (-25).
* Support 64 KiB authenticator data with its 32-byte client-data hash in verification.
* Report malformed WebAuthn responses and rejected algorithms as
  `FormatException`; cryptographic failures use `CryptoException`.
* Validate getInfo field types, composite CBOR labels, exact integer conversion
  and the 64-level nesting limit.
* Support omitted assertion descriptors through `requestedCredential`.
* Return immutable parsed authenticator bytes and reject malformed credential
  IDs, trailing data, tagged maps and inconsistent backup flags.

* Encode enterprise attestation as CTAP mode 1 or 2 through
  `enterpriseAttestationMode`; the existing boolean maps true to mode 1 and
  false to an omitted field.
* Require 1-64 byte user IDs and non-null names when generating registration
  options; CTAP user names remain optional.
* Add `CoseKey.verifySync()` alongside asynchronous `verify()`.
* Add CTAP configuration aliases, static encode/decode helpers and
  `src/authenticator_data.dart` with flat credential accessors.
* Validate COSE structure during authenticator-data parsing and snapshot byte
  buffers. Require typed makeCredential/getAssertion response fields.
* Encode getInfo AAGUID as bytes and omit PIN shared secrets from JSON/log output.
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
* Require explicit backend initialization and Dart 3.9+; see migration notes.
* Keep full v1 HMAC API results while applying 16-byte MACs to CTAP wire requests.

## 1.2.0

- Add the metadata-only extension for credential enumeration, including
  standard-response fallback.

## 1.1.0

- Make `name` and `displayName` optional in `PublicKeyCredentialUserEntity`

## 1.0.0

> And we're out of beta. We're releasing on time. -- Still Alive by GLaDOS

- Add FIDO2 `makeCredential` / `getAssertion` encoding / decoding with unit tests.
  - All data classes now have `toJson` and `toString`.
- Add stateless WebAuthn `Fido2Server` (registration / assertion flows, `rpIdHash` / `flags` / `signCount` checks, ES256 / EdDSA verification).
- Split public APIs into `fido2_client.dart` (CTAP client) and `fido2_server.dart` (server); adjust top-level exports.
- Expand COSE (EC2/OKP constants, CBOR map encoding, ES256 and EdDSA verifiers with strict DER parsing and low-S normalization) and add algorithm registry.
- Update dependencies (asn1lib, crypto, pointycastle, cbor).

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
