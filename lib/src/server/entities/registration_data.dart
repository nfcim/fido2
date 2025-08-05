import 'dart:typed_data';

import 'package:cbor/cbor.dart';

/// Represents the data returned after initiating a registration ceremony.
class RegistrationInitResponse {
  /// The FIDO2 options to be passed to the client-side `navigator.credentials.create()` call.
  /// This is a Map representation of the PublicKeyCredentialCreationOptions object.
  final Map<String, dynamic> creationOptions;

  /// A stateless session token that must be sent back to the server
  /// along with the authenticator's response.
  final String sessionToken;

  RegistrationInitResponse({
    required this.creationOptions,
    required this.sessionToken,
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
