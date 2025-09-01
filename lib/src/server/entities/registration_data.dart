import 'dart:typed_data';

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

  RegistrationResult({
    required this.credentialId,
    required this.credentialPublicKey,
  });

  @override
  Map<String, dynamic> toJson() => _$RegistrationResultToJson(this);
}
