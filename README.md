# fido2 for Dart

[![pub version](https://img.shields.io/pub/v/fido2)](https://pub.dev/packages/fido2)
[![Test](https://github.com/nfcim/fido2/actions/workflows/test.yml/badge.svg)](https://github.com/nfcim/fido2/actions/workflows/test.yml)

A Dart library for FIDO2 / WebAuthn with a Rust backend (native FFI and Web WASM).

- Parse and build CTAP2 commands / responses (CBOR)
- Interact with authenticators via CTAP2 (`ClientPin`, `CredentialManagement`)
- Stateless WebAuthn server for registration and authentication (signature verification, `rpIdHash` / `flags` / `signCount` checks)
- COSE verification: ES256, EdDSA (Ed25519), SM2 and ML-DSA-44/65/87

## Build and initialize

Requires Dart 3.9+, Rust 1.85+ and a platform linker. Web builds also use
`wasm-pack` and the `wasm32-unknown-unknown` target.

```sh
dart pub get
dart run fido2:setup
dart run fido2:setup --web
```

Initialize once per isolate with `await RustCrypto.initialize()`. Set
`libraryPath` or `FIDO2_CRYPTO_LIBRARY` to the native library. For Web, deploy
`build/fido2/web/`, load `fido2_crypto_loader.js` before Dart, and pass the
`fido2_crypto.js` URL through `wasmModuleUrl`.

See [migration and deployment](MIGRATION.md) for configuration and platform details.

## Usage - CTAP2 client

Import combined API:

```dart
import 'package:fido2/fido2.dart';

// Provide a CtapDevice implementation for your transport (see example/pcsc_example.dart)
Future<void> demo(CtapDevice device) async {
  await RustCrypto.initialize();
  final ctap = await Ctap2.create(device);
  print(ctap.info.versions);

  final cp = ClientPin(ctap, pinProtocol: PinProtocolV2());
  final retries = await cp.getPinRetries();
  print(retries);
}
```

More end-to-end CTAP examples are in [`example/pcsc_example.dart`](example/pcsc_example.dart).

Credential management also supports the
[metadata-only extension](doc/metadata-only-extension.md) for efficiently
listing credentials without transferring complete public keys.

## Usage - WebAuthn server

The server is stateless; you persist challenges, public keys, and counters.

```dart
import 'package:fido2/fido2.dart';
import 'package:cbor/cbor.dart';

await RustCrypto.initialize();
final server = Fido2Server(Fido2Config(rpId: 'example.com', rpName: 'Example'));

// 1) Registration
final regOptions = server.generateRegistrationOptions(
  'user@example.com', 'User', userHandle: accountUserId,
);
// send regOptions to client and store regOptions['challenge']

// After client returns base64url strings: clientDataJSON, attestationObject
final regResult = server.completeRegistration(
  clientDataBase64,
  attestationObjectBase64,
  expectedChallenge,
  offeredAlgorithms: (regOptions['pubKeyCredParams'] as List)
      .map((entry) => entry['alg'] as int).toList(),
  userHandle: accountUserId,
);
// Persist regResult.credentialId and regResult.credentialPublicKey (CborMap)

// 2) Authentication (Assertion)
final assertOptions = server.generateVerificationOptions();
// send to client and store assertOptions['challenge']

final verification = await server.completeVerification(
  clientDataBase64,
  authenticatorDataBase64,
  signatureBase64,
  expectedChallenge,
  regResult.credentialPublicKey,
  storedSignCount,
  userHandle: responseUserHandle,
  expectedUserHandle: regResult.userHandle,
  storedBackupEligible: regResult.backupEligible,
);

print(verification.userPresent);
```

Registration supports `fmt=none` and `fmt=packed` and validates the public key. Persist
`verification.signCount` and `verification.backedUp` after authentication.
`Fido2Config.signatureAlgorithms` controls algorithm order and defaults to ES256
and Ed25519. See [algorithm configuration](example/algorithm_config.dart).

### Packed attestation

Both `registerComplete()` and `completeRegistration()` verify packed signatures
over the original `authData || SHA256(clientDataJSON)` bytes. Packed self
attestation uses the credential's configured COSE algorithm. Certificate-based
packed attestation supports ES256/P-256 and Ed25519 certificate keys, independently
of the credential algorithm. ECDAA is not supported.

```dart
final server = Fido2Server(Fido2Config(
  rpId: 'dev.canokeys.org',
  attestation: AttestationConveyancePreference.direct,
));
final registered = server.registerComplete(
  payload['credential'] as Map<String, dynamic>,
  expectedChallenge: savedRequest.challenge,
  offeredAlgorithms: savedRequest.offeredAlgorithms,
  userHandle: accountUserId,
);
final evidence = registered.attestation!;
// evidence.format: 'none' or 'packed'
// evidence.type: AttestationType.none, self, or basic
// evidence.aaguid: 16 bytes; evidence.trustPath: leaf-first DER certificates
```

The default conveyance preference remains `none`, while the default accepted
formats are `{'none', 'packed'}`. Set `attestationFormats: {'none'}` to retain the
previous response policy. Conveyance preference is a client request, not a
requirement that the response contain a certificate.

The shared Rust native/WASM backend checks the packed leaf certificate's v3
profile, required Subject fields (PrintableString/UTF8String), Basic Constraints
`CA=false`, key algorithm and optional non-critical AAGUID extension. Signature
verification **does not establish certificate-chain or vendor trust**. Results
retain the evidence without labeling it trusted.

Applications that require trusted devices can set
`attestationVerifier: (evidence) => yourTrustPolicy(evidence)`. This synchronous
callback runs after protocol and signature verification for all accepted formats,
including `none` and self attestation; return `false` to reject registration.
The application owns chain validation against trusted roots/metadata, validity
periods and revocation checks. For asynchronous trust services, inspect the
returned evidence and complete those checks before persisting the credential.
An omitted callback accepts valid evidence without a vendor trust requirement.

## Serialization

Entities / requests use `json_serializable` for `toJson` and `toString` for readable logs.
Special cases with manual `toJson`: `CoseKey` and `CtapError`.

## Examples

- See [`example/`](example) for snippets and the PC/SC transport demo.

## Additional information

The following libraries might help:

* [flutter_nfc_kit](https://pub.dev/packages/flutter_nfc_kit) to communicate with NFC readers.
* [dart_pcsc](https://pub.dev/packages/dart_pcsc) to communicate with PC/SC readers.
