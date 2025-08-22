import 'dart:typed_data';

import 'package:cbor/cbor.dart';

/// Data parsed from the `attestedCredentialData` block of an `authenticatorData`
/// buffer. This contains the credential information.
class AttestedCredentialData {
  /// The AAGUID of the authenticator.
  final Uint8List aaguid;

  /// The credential ID.
  final Uint8List credentialId;

  /// The credential public key as a COSE_Key map.
  final CborMap credentialPublicKey;

  AttestedCredentialData({
    required this.aaguid,
    required this.credentialId,
    required this.credentialPublicKey,
  });
}

/// A structured representation of the `authenticatorData` buffer returned
/// by an authenticator.
///
/// It provides a safe way to parse and access the different fields of the
/// authenticator data.
class AuthenticatorData {
  /// The SHA-256 hash of the RP ID.
  final Uint8List rpIdHash;

  /// The flags byte.
  final int flags;

  /// The signature counter.
  final int signCount;

  /// The attested credential data, if present.
  final AttestedCredentialData? attestedCredentialData;

  /// Authenticator extension outputs, if present.
  final CborMap? extensions;

  AuthenticatorData({
    required this.rpIdHash,
    required this.flags,
    required this.signCount,
    this.attestedCredentialData,
    this.extensions,
  });

  /// User Present flag (bit 0).
  bool get userPresent => (flags & 0x01) != 0;

  /// User Verified flag (bit 2).
  bool get userVerified => (flags & 0x04) != 0;

  /// Attested Credential Data included flag (bit 6).
  bool get hasAttestedCredentialData => (flags & 0x40) != 0;

  /// Extension data included flag (bit 7).
  bool get hasExtensions => (flags & 0x80) != 0;

  /// Parses the raw authenticator data buffer into a structured object.
  ///
  /// This follows the structure defined in the WebAuthn specification:
  /// https://www.w3.org/TR/webauthn-2/#sctn-authenticator-data
  static AuthenticatorData parse(Uint8List authDataBytes) {
    var offset = 0;

    // Helper to read a chunk of bytes and advance the offset.
    Uint8List readBytes(int length) {
      if (authDataBytes.length < offset + length) {
        throw FormatException(
          'Authenticator data too short. Needed $length bytes at offset $offset, but length is ${authDataBytes.length}',
        );
      }
      final slice = authDataBytes.sublist(offset, offset + length);
      offset += length;
      return slice;
    }

    final rpIdHash = readBytes(32);
    final flags = readBytes(1)[0];
    final signCountBytes = readBytes(4);
    final signCount = ByteData.view(
      signCountBytes.buffer,
      signCountBytes.offsetInBytes,
    ).getUint32(0, Endian.big);

    AttestedCredentialData? attestedCredentialData;
    CborMap? extensions;

    final hasAttestedData = (flags & 0x40) != 0;
    final hasExtensionsData = (flags & 0x80) != 0;

    if (hasAttestedData) {
      final aaguid = readBytes(16);
      final credIdLengthBytes = readBytes(2);
      final credentialIdLength = ByteData.view(
        credIdLengthBytes.buffer,
        credIdLengthBytes.offsetInBytes,
      ).getUint16(0, Endian.big);
      final credentialId = readBytes(credentialIdLength);

      // The rest of the buffer contains the CBOR-encoded public key and, if present, extensions.
      final remainingBytes = authDataBytes.sublist(offset);
      if (remainingBytes.isEmpty) {
        throw FormatException(
            'Authenticator data ended unexpectedly. Missing credential public key.');
      }

      final decoded = cbor.decode(remainingBytes);
      final List<CborValue> cborItems;
      if (decoded is CborList) {
        cborItems = decoded;
      } else {
        cborItems = [decoded];
      }

      if (cborItems.isEmpty || cborItems.first is! CborMap) {
        throw FormatException(
            'Could not parse credential public key, expected a CborMap.');
      }
      final credentialPublicKey = cborItems.first as CborMap;

      attestedCredentialData = AttestedCredentialData(
        aaguid: aaguid,
        credentialId: credentialId,
        credentialPublicKey: credentialPublicKey,
      );

      // If extensions are also present, they are the second item in the CBOR list.
      if (hasExtensionsData &&
          cborItems.length > 1 &&
          cborItems[1] is CborMap) {
        extensions = cborItems[1] as CborMap;
      }
    } else if (hasExtensionsData) {
      // Attested data is not present, but extensions are.
      final extBytes = authDataBytes.sublist(offset);
      if (extBytes.isNotEmpty) {
        final decodedExt = cbor.decode(extBytes);
        if (decodedExt is CborMap) {
          extensions = decodedExt;
        }
      }
    }

    return AuthenticatorData(
      rpIdHash: rpIdHash,
      flags: flags,
      signCount: signCount,
      attestedCredentialData: attestedCredentialData,
      extensions: extensions,
    );
  }
}
