# fido2 for Dart

[![Test](https://github.com/nfcim/fido2/actions/workflows/test.yml/badge.svg)](https://github.com/nfcim/fido2/actions/workflows/test.yml)

A pure Dart library to parse FIDO2 request / response and interactive with FIDO2 authenticators.

## Features

1. Convert FIDO2 request / response from / to CBOR.
2. Call `ClientPin` and `CredentialManagement` commands to an authenticator in CTAP2 protocol.

See [example](example) for more information.

## Additional information

The following libraries might help:

* [flutter_nfc_kit](https://pub.dev/packages/flutter_nfc_kit) to communicate with NFC readers.
* [dart_pcsc](https://pub.dev/packages/dart_pcsc) to communicate with PC/SC readers.
