# Example for fido2 package

## `pcsc_example.dart`

This example shows how to use `fido2` to interact with a FIDO2 authenticator
thats implements CCID protocol and connected via PC/SC interface.

`dart_pcsc` package is used to interact with native PC/SC API
(`winscard.h` on Windows, or `pcsclite` on Linux / macOS).
