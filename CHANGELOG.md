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
