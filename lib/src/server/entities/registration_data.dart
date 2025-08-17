import 'dart:typed_data';

import 'package:cbor/cbor.dart';

/// The result of a successful registration verification.
class RegistrationResult {
  /// A unique identifier for the new credential.
  final Uint8List credentialId;

  /// The public key of the new credential.
  final CborMap credentialPublicKey;

  RegistrationResult({
    required this.credentialId,
    required this.credentialPublicKey,
  });
}
