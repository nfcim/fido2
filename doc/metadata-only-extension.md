# Credential Management Metadata-Only Extension

The metadata-only extension reduces the amount of data transferred while
enumerating discoverable credentials. It is intended for management clients
that need to list credentials but do not need each credential's complete
public key.

## Motivation

The standard `enumerateCredentialsBegin` and
`enumerateCredentialsGetNextCredential` responses include a COSE public key.
That key is unnecessary for common management operations such as displaying a
credential, selecting one for deletion, or updating its user information.

Transferring every public key makes enumeration slower on constrained
transports. The cost becomes more significant for algorithms whose public keys
are substantially larger than traditional elliptic-curve keys. Omitting the
key improves enumeration latency without removing any metadata needed by these
management workflows.

The extension reuses the standard credential management command and
subcommands instead of defining a parallel enumeration protocol. This keeps
the standard response fields, pagination behavior, authorization model, and
error handling unchanged.

## Begin Request

The request uses `authenticatorCredentialManagement` (`0x0A`) with
`enumerateCredentialsBegin` (`0x04`). The `subCommandParams` map contains the
standard RP ID hash and the private metadata-only flag:

```cbor
{
  0x01: h'<32-byte rpIdHash>',
  0x80: true
}
```

The complete request has the standard credential management shape:

```cbor
{
  0x01: 0x04,
  0x02: {
    0x01: h'<32-byte rpIdHash>',
    0x80: true
  },
  0x03: pinUvAuthProtocol,
  0x04: pinUvAuthParam
}
```

`pinUvAuthParam` authenticates the complete parameter map, including the
extension flag:

```text
subCommand || canonicalCbor(subCommandParams)
```

Including the flag in the authenticated message prevents the requested mode
from being changed independently of the authenticated request. Integer keys
are encoded in canonical order, so `0x01` precedes `0x80`.

## Response

A metadata-only response omits the standard `publicKey` field (`0x08`) and
returns the credential's COSE algorithm ID in private field `0x80`:

```cbor
{
  ...standard credential fields,
  0x80: -7
}
```

The algorithm ID is retained because clients may need to identify the type of
credential even when they do not need the full key. It is small, stable, and
already defined by COSE, so duplicating the key solely to preserve this
information would defeat the purpose of the extension.

Currently used algorithm IDs are:

| ID | Algorithm |
| ---: | --- |
| `-7` | ES256 |
| `-8` | EdDSA |
| `-49` | ML-DSA-65 |

All other response fields retain their standard credential management meaning
and encoding.

## Pagination State

The metadata-only flag is sent only with Begin. The authenticator retains the
mode for the active enumeration, so subsequent
`enumerateCredentialsGetNextCredential` (`0x05`) requests contain no
`subCommandParams`.

This design follows the existing stateful enumeration model and avoids adding
parameters to a subcommand that does not accept them. Sending `0x80` with
GetNext is invalid and may result in `CTAP2_ERR_INVALID_SUBCOMMAND`.

Starting another normal Begin request without `0x80` replaces the active
enumeration state and restores standard responses with complete public keys.

## Compatibility

Clients distinguish the response form by its fields:

1. If `0x80` is present and `0x08` is absent, parse a metadata-only response.
2. If `0x08` is present, parse the standard response and obtain the algorithm
   ID from the COSE public key.

The second case allows a client to request metadata-only enumeration while
remaining compatible with implementations that return the standard response
shape. The `CmCredentialMetadata.metadataOnly` property reports which response
form was received, and `publicKey` remains available when the standard form is
used.

## Dart API

Use `CredentialManagement.enumerateCredentialsMetadataOnly` to request the
extension:

```dart
final credentials =
    await credentialManagement.enumerateCredentialsMetadataOnly(rpIdHash);

for (final credential in credentials) {
  print(credential.credentialId);
  print(credential.coseAlgorithm);
}
```

The existing `enumerateCredentials` API remains unchanged and always requests
standard responses with complete public keys.
