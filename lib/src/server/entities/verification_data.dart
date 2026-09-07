import 'dart:typed_data';
import 'package:fido2/src/utils/serialization.dart';

import 'package:json_annotation/json_annotation.dart';

part 'verification_data.g.dart';

/// The result of a successful assertion (verification).
@JsonSerializable(createFactory: false, explicitToJson: true)
class VerificationResult with JsonToStringMixin {
  /// Whether the authenticator reported the user was present (UP flag).
  final bool userPresent;

  /// Whether the authenticator reported the user was verified (UV flag).
  final bool userVerified;

  /// Signature counter returned by the authenticator.
  final int signCount;

  /// Raw authenticator data bytes that were verified (optional but useful).
  final Uint8List authenticatorData;

  final bool backupEligible;
  final bool backedUp;

  VerificationResult({
    required this.userPresent,
    required this.userVerified,
    required this.signCount,
    required this.authenticatorData,
    this.backupEligible = false,
    this.backedUp = false,
  });

  @override
  Map<String, dynamic> toJson() => _$VerificationResultToJson(this);
}

/// Verified state to persist atomically after successful authentication.
@JsonSerializable(createFactory: false, explicitToJson: true)
class AuthenticationResult with JsonToStringMixin {
  @override
  Map<String, dynamic> toJson() => _$AuthenticationResultToJson(this);

  final int signCount;
  final bool backedUp;
  const AuthenticationResult({required this.signCount, required this.backedUp});
}
