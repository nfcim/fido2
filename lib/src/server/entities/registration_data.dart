import 'dart:typed_data';
import '../../cose.dart';

import 'package:cbor/cbor.dart';
import 'package:fido2/src/utils/serialization.dart';

import 'package:json_annotation/json_annotation.dart';

part 'registration_data.g.dart';

/// The result of a successful registration verification.
@JsonSerializable(createFactory: false, explicitToJson: true)
class RegistrationResult with JsonToStringMixin {
  /// A unique identifier for the new credential.
  final Uint8List credentialId;

  /// The public key of the new credential.
  final CborMap credentialPublicKey;

  final int signCount;
  final bool backupEligible;
  final bool backedUp;
  final List<int>? userHandle;

  RegistrationResult({
    required this.credentialId,
    required this.credentialPublicKey,
    this.signCount = 0,
    this.backupEligible = false,
    this.backedUp = false,
    this.userHandle,
  });

  @override
  Map<String, dynamic> toJson() => _$RegistrationResultToJson(this);
}

@JsonSerializable(createFactory: false, explicitToJson: true)
class RegisteredCredential with JsonToStringMixin {
  @override
  Map<String, dynamic> toJson() => _$RegisteredCredentialToJson(this);

  final List<int> id;
  final CoseKey publicKey;
  final int signCount;
  final bool backupEligible;
  final bool backedUp;
  final List<int>? userHandle;
  RegisteredCredential({
    required List<int> id,
    required this.publicKey,
    this.signCount = 0,
    this.backupEligible = false,
    this.backedUp = false,
    List<int>? userHandle,
  }) : id = List.unmodifiable(id),
       userHandle = userHandle == null ? null : List.unmodifiable(userHandle) {
    if (backedUp && !backupEligible) {
      throw ArgumentError('Backup state requires backup eligibility');
    }
    if (userHandle != null &&
        (userHandle.isEmpty ||
            userHandle.length > 64 ||
            userHandle.any((b) => b < 0 || b > 255))) {
      throw ArgumentError('User handle must contain 1 to 64 bytes');
    }
  }
}

@JsonSerializable(createFactory: false, explicitToJson: true)
class RegistrationRequest with JsonToStringMixin {
  @override
  Map<String, dynamic> toJson() => _$RegistrationRequestToJson(this);

  final Map<String, dynamic> publicKey;
  final List<int> challenge;
  final List<int> offeredAlgorithms;
  RegistrationRequest(this.publicKey, this.challenge, this.offeredAlgorithms);
}
