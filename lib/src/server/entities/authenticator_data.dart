import 'dart:typed_data';
import '../../cose.dart';
import '../../strict_cbor.dart';

import 'package:cbor/cbor.dart';
import 'package:fido2/src/utils/serialization.dart';

import 'package:json_annotation/json_annotation.dart';

part 'authenticator_data.g.dart';

/// Data parsed from the `attestedCredentialData` block of an `authenticatorData`
/// buffer. This contains the credential information.
@JsonSerializable(createFactory: false, explicitToJson: true)
class AttestedCredentialData with JsonToStringMixin {
  /// The AAGUID of the authenticator.
  final Uint8List aaguid;

  /// The credential ID.
  final Uint8List credentialId;

  /// The credential public key as a COSE_Key map.
  final CborMap credentialPublicKey;

  AttestedCredentialData({
    required Uint8List aaguid,
    required Uint8List credentialId,
    required this.credentialPublicKey,
  }) : aaguid = Uint8List.fromList(aaguid).asUnmodifiableView(),
       credentialId = Uint8List.fromList(credentialId).asUnmodifiableView();

  @override
  Map<String, dynamic> toJson() => _$AttestedCredentialDataToJson(this);
}

/// A structured representation of the `authenticatorData` buffer returned
/// by an authenticator.
@JsonSerializable(createFactory: false, explicitToJson: true)
class AuthenticatorData with JsonToStringMixin {
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

  @JsonKey(includeToJson: false)
  final Uint8List bytes;
  final CoseConfiguration? _configuration;
  CoseKey? _parsedKey;
  @JsonKey(includeToJson: false)
  List<int>? get aaguid => attestedCredentialData?.aaguid;
  bool get backupEligible => flags & 8 != 0;
  bool get backedUp => flags & 16 != 0;
  @JsonKey(includeToJson: false)
  List<int>? get credentialId => attestedCredentialData?.credentialId;
  @JsonKey(includeToJson: false)
  CoseKey? get credentialPublicKey => attestedCredentialData == null
      ? null
      : _parsedKey ??= CoseKey.fromCborMap(
          attestedCredentialData!.credentialPublicKey,
          configuration: _configuration,
        );

  AuthenticatorData({
    required Uint8List rpIdHash,
    required this.flags,
    required this.signCount,
    this.attestedCredentialData,
    this.extensions,
    Uint8List? bytes,
    CoseConfiguration? configuration,
  }) : rpIdHash = Uint8List.fromList(rpIdHash).asUnmodifiableView(),
       bytes = Uint8List.fromList(bytes ?? []).asUnmodifiableView(),
       _configuration = configuration;

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
  static AuthenticatorData parse(
    List<int> input, {
    CoseConfiguration? configuration,
  }) {
    if (input.length < 37 ||
        input.length > 65536 ||
        input.any((b) => b < 0 || b > 255)) {
      throw const FormatException('Invalid authenticator data length or bytes');
    }
    final bytes = Uint8List.fromList(input);
    var offset = 37;
    final flags = bytes[32];
    if (flags & 16 != 0 && flags & 8 == 0) {
      throw const FormatException('Backup state requires backup eligibility');
    }
    final signCount = ByteData.sublistView(bytes, 33, 37).getUint32(0);
    Uint8List readBytes(int length) {
      if (offset + length > bytes.length) {
        throw const FormatException('Truncated authenticator data');
      }
      final result = bytes.sublist(offset, offset + length);
      offset += length;
      return result.asUnmodifiableView();
    }

    CborMap readMap() {
      final (value, end) = readCborItem(bytes, offset);
      offset = end;
      if (value is! CborMap || value.tags.isNotEmpty) {
        throw const FormatException('Expected untagged CBOR map');
      }
      return value;
    }

    AttestedCredentialData? attested;
    if (flags & 64 != 0) {
      final aaguid = readBytes(16);
      final lengthBytes = readBytes(2);
      final length = lengthBytes[0] * 256 + lengthBytes[1];
      if (length == 0 || length > 1023) {
        throw const FormatException('Invalid credential ID length');
      }
      final id = readBytes(length);
      attested = AttestedCredentialData(
        aaguid: aaguid,
        credentialId: id,
        credentialPublicKey: readMap(),
      );
    }
    CborMap? extensions;
    if (flags & 128 != 0) {
      extensions = readMap();
      if (extensions.keys.any((k) => k is! CborString)) {
        throw const FormatException('Expected extension text keys');
      }
    }
    if (offset != bytes.length) {
      throw const FormatException('Trailing authenticator data');
    }
    final result = AuthenticatorData(
      rpIdHash: bytes.sublist(0, 32),
      flags: flags,
      signCount: signCount,
      attestedCredentialData: attested,
      extensions: extensions,
      bytes: bytes,
      configuration: configuration,
    );
    result.credentialPublicKey;
    return result;
  }

  @override
  Map<String, dynamic> toJson() => _$AuthenticatorDataToJson(this);
}
