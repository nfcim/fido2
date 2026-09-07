# Rust backend and migration

## API changes

Initialize the backend once per Dart isolate with `await RustCrypto.initialize()`.
Repeated calls use identical options; conflicting options produce `StateError`.
Failed initialization can be retried.

* `AuthenticatorInfo.algorithms` is now `List<Map<String, dynamic>>?` because
  each entry contains a string `type`.
* Every COSE key requires integer `kty` (1) and `alg` (3), including
  `UnsupportedKey`.
* `toCbor()` remains available alongside `toCborMap()`. Native lists in unknown
  fields encode as arrays; use `CborBytes` for byte strings.
* `completeRegistration()` accepts `offeredAlgorithms` and `userHandle`.
  `completeVerification()` accepts `userHandle`, `expectedUserHandle`,
  `requireUserHandle` and `storedBackupEligible`; its result includes backup state.
* PIN v1 `authenticate()` returns the full 32-byte MAC.
  `authenticateParam()` produces the CTAP wire MAC: 16 bytes for v1, 32 for v2.

COSE parsing and encoding work before initialization. `CoseKey.fromCbor(bytes)`
checks duplicate labels, including nested maps, before constructing a key.
Use `fromCborMap()` for an already decoded map. Public key fields are immutable;
unknown fields retain their CBOR types and tags. Roundtrips preserve values
rather than the original wire encoding.

`key.validate()` checks mathematical validity in Rust. `key.verify()` retains its
`Future<void>` return type. `key.verifySync()` provides synchronous verification. `RustCrypto.verify()` returns
a boolean for validly encoded signatures and throws `CryptoException` for
invalid inputs or unsupported modes.

The client/server exports, request `encode()` and response `decode()` methods,
JSON serialization, COSE constants and `EdDSA` class retain their existing APIs.
Credential management supports metadata-only enumeration and optional user names.

## Algorithms

The shared Rust backend implements signatures, SHA-256, SM3, ECDH, HKDF-SHA-256,
HMAC-SHA-256, AES-256-CBC, random bytes and CTAP ephemeral key generation.

| Algorithm | COSE alg | COSE kty | Public fields | Signature |
| --- | --- | --- | --- | --- |
| ES256 | -7 | EC2 = 2 | -1: 1, -2: x, -3: y (32 bytes each) | DER by default; explicit raw |
| ESP256 | -9 | EC2 = 2 | P-256 fields | DER by default; explicit raw |
| EdDSA (Ed25519) | -8 | OKP = 1 | -1: 6, -2: key (32 bytes) | 64 bytes |
| Ed25519 | -19 | OKP = 1 | Ed25519 fields | 64 bytes |
| ML-DSA-44 | -48 | AKP = 7 | -1: key (1312 bytes) | 2420 bytes |
| ML-DSA-65 | -49 | AKP = 7 | -1: key (1952 bytes) | 3309 bytes |
| ML-DSA-87 | -50 | AKP = 7 | -1: key (2592 bytes) | 4627 bytes |
| SM2 profile | Configured | EC2 = 2 | -1: configured curve, -2: x, -3: y (32 bytes each) | Explicit raw or DER |
| ECDH-ES+HKDF-256 | -25 | EC2 = 2 | P-256 fields | Key agreement |

Identifiers follow [IANA COSE](https://www.iana.org/assignments/cose/cose.xhtml),
[RFC 9052](https://www.rfc-editor.org/rfc/rfc9052),
[RFC 9053](https://www.rfc-editor.org/rfc/rfc9053),
[RFC 9864](https://www.rfc-editor.org/rfc/rfc9864) and
[RFC 9964](https://www.rfc-editor.org/rfc/rfc9964).

SM2 uses sm2p256v1 and the SM3/ZA verification process from GB/T 32918.2 and
GB/T 32905. Configure both endpoints with matching identifiers, signature
encoding and ID. `Sm2Configuration` accepts private-use identifiers below
-65536. `allowUnassignedIdentifiers: true` additionally permits algorithms
-256 through -54 and curves 9 through 255. These are compatibility identifiers;
SM2 has no assigned IANA COSE algorithm or curve.

The SM2 ID is UTF-8, defaults to `1234567812345678`, and allows up to 8191 bytes.
An empty ID is a distinct value. Raw signatures concatenate 32-byte big-endian
r and s; DER signatures encode two positive INTEGERs in a SEQUENCE. Select the
encoding explicitly. ES256 accepts high-S and low-S signatures. Ed25519 uses
strict verification of ordinary Ed25519 signatures.

COSE ML-DSA uses **Pure ML-DSA with empty context**, as specified by RFC 9964.
The low-level API supports Pure ML-DSA contexts of 0-255 bytes. HashML-DSA
requests produce `unsupported_mode`.

AES-CBC input consists of complete blocks with protocol-supplied PIN padding.

## WebAuthn

`Fido2Config.signatureAlgorithms` is ordered and defaults to `[-7, -8]`.
Configure any supported signature algorithm individually or in a mixed list.
The browser and authenticator must support the selected algorithms.

```dart
final server = Fido2Server(Fido2Config(
  rpId: 'example.com',
  origins: {'https://example.com'},
  signatureAlgorithms: [MLDSA87.algorithm, ES256.algorithm],
));
final options = server.generateRegistrationOptions('alice', 'Alice',
    userHandle: accountUserId);
// Persist options and accountUserId with the session.
final registered = server.completeRegistration(
  clientDataBase64, attestationObjectBase64, options['challenge'],
  offeredAlgorithms: (options['pubKeyCredParams'] as List)
      .map((entry) => entry['alg'] as int).toList(),
  userHandle: accountUserId,
);
```

Registration supports `fmt=none` and validates the credential public key.
Attestation certificate trust is outside this API. Completion checks the
request's `offeredAlgorithms` and current policy; omitting the parameter uses
current policy. Persist configured compatibility profiles with application
configuration so stored keys can be loaded with the same identifiers.

Store `userHandle`, `signCount`, `backupEligible` and `backedUp` with each
credential. Returned user handles must match the trusted account ID. Older
records can supply it through `expectedUserHandle`. For usernameless login,
resolve the credential and handle from the same account and require a handle:

```dart
final result = await server.completeVerification(
  clientDataBase64, authenticatorDataBase64, signatureBase64,
  storedChallenge, registered.credentialPublicKey, registered.signCount,
  userHandle: responseUserHandle,
  expectedUserHandle: accountUserId,
  requireUserHandle: true,
  storedBackupEligible: registered.backupEligible,
);
// Atomically persist result.signCount and result.backedUp.
```

Backup eligibility (BE) is fixed at registration; backup state (BS) can change
in either direction. Applications bind challenges and credentials to accounts
and sessions, enforce challenge expiry and single use, and persist verified
state atomically.

Responses use WebAuthn JSON with base64url byte fields. Origin matching is
exact and requires same-origin ceremonies. Signature messages are
`authenticatorData || SHA256(clientDataJSON)`; RP ID hashes are
`SHA256(UTF8(rpId))`.

The JSON response convenience methods `registerBegin`, `registerComplete`,
`authenticateBegin` and `authenticateCompleteResult` use the same verifier.

`AuthenticatorData.parse()` consumes the public key and extension CBOR items
separately. It supports large ML-DSA keys and validates truncation, trailing
data and duplicate labels. Limits are 64 KiB for authenticator data, 1023 bytes
for credential IDs and 64 levels of CBOR nesting.

## Build and deployment

Requires Dart 3.9+, Rust 1.85+, Cargo and a platform linker. Web builds also
require `wasm-pack` and the `wasm32-unknown-unknown` Rust target.

```sh
dart run fido2:setup --output=build/fido2
dart run fido2:setup --web --output=build/fido2
```

Native builds use the committed Cargo lockfile and place host artifacts under
`build/fido2/native/release`. Set `initialize(libraryPath: ...)` to the library's
absolute path or use `FIDO2_CRYPTO_LIBRARY`. Otherwise, the OS loader resolves
the standard library filename.

Linux, macOS and Windows builds run in CI. Android and iOS integration requires
target-specific NDK/Xcode builds and application packaging. iOS defaults to
`DynamicLibrary.process()`; link the static library and retain exported
`fido2_*` symbols. The package distributes Rust source. Application builders
need Rust or matching prebuilt artifacts; packaged applications use the
bundled artifacts.

For Web, deploy `build/fido2/web/` and load the bridge before the Dart app:

```html
<script src="/crypto/fido2_crypto_loader.js"></script>
```

```dart
await RustCrypto.initialize(wasmModuleUrl: '/crypto/fido2_crypto.js');
```

The URL resolves against the page's base URI; the JS module loads the adjacent
WASM file. Serve over HTTP(S) with `application/wasm` and a CSP that permits
module loading and WASM compilation. Deploy JS and WASM as one version.

## Runtime limits

The native/WASM bridge allows 1 MiB per JSON request and 64 KiB per binary
field. HKDF output is limited to 8160 bytes; random output to 65536 bytes.
Native bridge buffers and Rust request buffers are cleared on release.
Dart and JS managed copies of secret material are subject to garbage collection
and cannot be reliably erased.

Rust dependencies and versions are recorded in `rust/Cargo.toml` and
`rust/Cargo.lock`. The SM2 and ML-DSA upstream implementations have not been
independently audited. Include dependency licenses when distributing binaries.

## Tests

```sh
cargo test --manifest-path rust/Cargo.toml --locked
cargo clippy --manifest-path rust/Cargo.toml --locked --all-targets -- -D warnings
dart run fido2:setup
dart run fido2:setup --web
dart run build_runner build
dart run tool/test.dart
dart run tool/test.dart -p chrome
dart run tool/test.dart -p chrome -c dart2wasm test/crypto_test.dart test/webauthn_test.dart test/initialization_test.dart test/fido2_base_test.dart test/cbor_boundaries_test.dart test/fido2_server_auth_data_test.dart test/fido2_credmgmt_test.dart
dart analyze
dart format --output=none --set-exit-if-changed .
```

Tests cover RFC 9964 ML-DSA vectors, the SM2 standard example, RFC 8032
Ed25519, RFC 6979 P-256, RFC 5869 HKDF, HMAC/SHA/SM3 and NIST AES-CBC vectors.
Independent Dart implementations verify PIN ECDH/KDF/AES/MAC results.
Integration fixtures cover registration and authentication for every signature
algorithm. Additional tests cover account binding, backup-state transitions,
CBOR types, duplicate labels, malformed responses and initialization.

Fixtures are committed. `tool/import_vectors.py` imports RFC XML examples;
`cargo run --manifest-path rust/Cargo.toml --example generate_fixtures`
generates integration fixtures; `tool/embed_fixtures.py` embeds them for
VM and Web tests.

## USB testing

`dart run tool/usb_key_test.dart` reads authenticator information and PIN retry
counts over PC/SC/CCID, validates the P-256 public key and runs host PIN v1/v2
encapsulation.

Create non-resident credentials and verify device assertions with:

```sh
dart run tool/usb_key_test.dart --sign
dart run tool/usb_key_test.dart --sign --algorithm=-49
dart run tool/usb_key_test.dart --sign --algorithm=-54 --canokey-sm2
```

Touch the key for credential creation and assertion. Signing can advance the
device counter. `--canokey-sm2` selects algorithm -54, curve 9, the default
SM2 ID and raw signatures.
