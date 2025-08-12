import 'dart:typed_data';

import 'package:cbor/cbor.dart';

/// Represents the data returned after initiating a registration ceremony.
class RegistrationInitResponse {
  /// A unique identifier for this registration session.
  /// This must be passed back to the `completeRegistration` call.
  final String sessionId;

  /// The FIDO2 options to be passed to the client-side `navigator.credentials.create()` call.
  /// This is a Map representation of the PublicKeyCredentialCreationOptions object.
  final Map<String, dynamic> creationOptions;

  RegistrationInitResponse({
    required this.sessionId,
    required this.creationOptions,
  });
}

/// The result of a successful registration ceremony.
/// This data should be stored in the database, associated with the user.
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
