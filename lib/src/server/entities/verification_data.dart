import 'dart:typed_data';

/// The result of a successful assertion (verification).
class VerificationResult {
  /// Whether the authenticator reported the user was present (UP flag).
  final bool userPresent;

  /// Whether the authenticator reported the user was verified (UV flag).
  final bool userVerified;

  /// Signature counter returned by the authenticator.
  final int signCount;

  /// Raw authenticator data bytes that were verified (optional but useful).
  final Uint8List authenticatorData;

  VerificationResult({
    required this.userPresent,
    required this.userVerified,
    required this.signCount,
    required this.authenticatorData,
  });
}
