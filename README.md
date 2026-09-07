# fido2 for Dart

[![Test](https://github.com/nfcim/fido2/actions/workflows/test.yml/badge.svg)](https://github.com/nfcim/fido2/actions/workflows/test.yml)

A Dart library for FIDO2/CTAP2 and WebAuthn, with all cryptographic operations
implemented by a shared Rust backend (FFI on native platforms, WASM on Web).

## Features

* Encode and parse CTAP2 requests, responses and COSE keys.
* Run `ClientPin` and `CredentialManagement` commands.
* Verify ES256, Ed25519, SM2 and ML-DSA-44/65/87 signatures.
* Configure WebAuthn algorithms, register credentials and verify assertions.

## Build and initialize

Requires Dart 3.4+ and Rust 1.85+ with Cargo and a platform linker. Install
`wasm-pack` and the `wasm32-unknown-unknown` Rust target for Web builds.

```sh
dart pub get
dart run fido2:setup
# For a Web application:
dart run fido2:setup --web
```

Before any cryptographic operation, await initialization once per Dart isolate:

```dart
import 'package:fido2/fido2.dart';

await RustCrypto.initialize(
  libraryPath: '/absolute/path/to/libfido2_crypto.dylib',
);
```

Use `.so` on Linux/Android and `fido2_crypto.dll` on Windows. Initialization can
also use `FIDO2_CRYPTO_LIBRARY` on native platforms. COSE parsing/encoding alone
does not require the backend; call `key.validate()` for mathematical validation.

For Web, deploy the generated `build/fido2/web/` directory, include
`fido2_crypto_loader.js` before the Dart application, then initialize with the
URL of `fido2_crypto.js`. The adjacent `.wasm` file must also be deployed.

See [migration, algorithms, deployment and tests](MIGRATION.md) and
[algorithm configuration example](example/algorithm_config.dart).

## Additional information

The following libraries might help:

* [flutter_nfc_kit](https://pub.dev/packages/flutter_nfc_kit) to communicate with NFC readers.
* [dart_pcsc](https://pub.dev/packages/dart_pcsc) to communicate with PC/SC readers.
