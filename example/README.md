# Examples

Build the Rust backend with `dart run fido2:setup` before running examples.

## `algorithm_config.dart`

Configures default, single-algorithm and mixed WebAuthn registration requests
for ES256, Ed25519, SM2 and ML-DSA.

## `pcsc_example.dart`

Communicates with a CCID FIDO2 authenticator over PC/SC.

The `dart_pcsc` package provides access to the platform PC/SC API.
