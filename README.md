# fido2 for Dart

[![pub version](https://img.shields.io/pub/v/fido2)](https://pub.dev/packages/fido2)
[![Test](https://github.com/nfcim/fido2/actions/workflows/test.yml/badge.svg)](https://github.com/nfcim/fido2/actions/workflows/test.yml)

A pure Dart library for FIDO2 / WebAuthn.

- Parse and build CTAP2 commands / responses (CBOR)
- Interact with authenticators via CTAP2 (`ClientPin`, `CredentialManagement`)
- Stateless WebAuthn server for registration and authentication (signature verification, `rpIdHash` / `flags` / `signCount` checks)
- COSE verification: ES256 and EdDSA (Ed25519)

## Usage — CTAP2 client

Import combined API:

```dart
import 'package:fido2/fido2.dart';

// Provide a CtapDevice implementation for your transport (see example/pcsc_example.dart)
Future<void> demo(CtapDevice device) async {
  final ctap = await Ctap2.create(device);
  print(ctap.info.versions);

  final cp = ClientPin(ctap, pinProtocol: PinProtocolV2());
  final retries = await cp.getPinRetries();
  print(retries);
}
```

More end-to-end CTAP examples are in [`example/pcsc_example.dart`](example/pcsc_example.dart).

## Usage — WebAuthn server

The server is stateless; you persist challenges, public keys, and counters.

```dart
import 'package:fido2/fido2.dart';
import 'package:cbor/cbor.dart';

final server = Fido2Server(Fido2Config(rpId: 'example.com', rpName: 'Example'));

// 1) Registration
final regOptions = server.generateRegistrationOptions('user@example.com', 'User');
// send regOptions to client and store regOptions['challenge']

// After client returns base64url strings: clientDataJSON, attestationObject
final regResult = server.completeRegistration(
  clientDataBase64,
  attestationObjectBase64,
  expectedChallenge,
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
  storedSignCount, // 0 if unknown
);

print(verification.userPresent);
```

Notes:

- Attestation statement is not verified (use 'none' attestation).
- Supported algorithms: ES256, EdDSA (Ed25519) with strict DER parsing and low-S normalization.

## Serialization

Entities / requests use `json_serializable` for `toJson` and `toString` for readable logs.
Special cases with manual `toJson`: `CoseKey` and `CtapError`.

## Examples

- See [`example/`](example) for snippets and the PC/SC transport demo.

## Additional information

The following libraries might help:

* [flutter_nfc_kit](https://pub.dev/packages/flutter_nfc_kit) to communicate with NFC readers.
* [dart_pcsc](https://pub.dev/packages/dart_pcsc) to communicate with PC/SC readers.
