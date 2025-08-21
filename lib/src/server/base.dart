import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cbor/cbor.dart';
import 'package:crypto/crypto.dart';
import 'package:fido2/src/cose.dart';

import 'config.dart';
import 'entities/authenticator_data.dart';
import 'entities/registration_data.dart';
import 'entities/verification_data.dart';

/// A stateless FIDO2/WebAuthn server implementation.
class Fido2Server {
  final Fido2Config config;
  final Random _secureRandom = Random.secure();

  // Single source of truth for supported signature algorithms
  static const List<int> _supportedAlgorithms = [
    ES256.algorithm, // -7
    EdDSA.algorithm, // -8 (Ed25519)
  ];

  Fido2Server(this.config);

  /// Helper to add padding to base64url strings if missing.
  String _padBase64(String base64) {
    return base64.padRight((base64.length + 3) & ~3, '=');
  }

  /// Generates a cryptographically random challenge.
  Uint8List _generateChallenge() {
    final challenge = Uint8List(32);
    for (var i = 0; i < challenge.length; i++) {
      challenge[i] = _secureRandom.nextInt(256);
    }
    return challenge;
  }

  /// Generates registration options for the client.
  /// The calling server is responsible for storing the challenge.
  Map<String, dynamic> generateRegistrationOptions(
      String username, String displayName) {
    final challenge = _generateChallenge();

    final options = {
      'rp': {'id': config.rpId, 'name': config.rpName},
      'user': {
        'id': base64Url.encode(utf8.encode(username)),
        'name': username,
        'displayName': displayName,
      },
      'challenge': base64Url.encode(challenge),
      'pubKeyCredParams': _supportedAlgorithms
          .map((alg) => {'type': 'public-key', 'alg': alg})
          .toList(growable: false),
      'timeout': 60000,
      'attestation': 'none',
    };

    return options;
  }

  /// Generates verification (assertion) options for the client.
  /// The RP should persist the challenge and tie it to the login transaction.
  Map<String, dynamic> generateVerificationOptions() {
    final challenge = _generateChallenge();
    return {
      'challenge': base64Url.encode(challenge),
      'timeout': 60000,
      'rpId': config.rpId,
      // allowCredentials, userVerification, etc. can be added by integrators as needed
    };
  }

  /// Verifies the authenticator's response and completes the registration.
  ///
  /// Throws an exception if any part of the verification fails.
  /// Returns a [RegistrationResult] on success, which should be stored.
  RegistrationResult completeRegistration(
    String clientDataBase64,
    String attestationObjectBase64,
    String expectedChallenge,
  ) {
    // 1. Decode and verify clientDataJSON
    final clientDataJSON =
        utf8.decode(base64Url.decode(_padBase64(clientDataBase64)));
    final clientData = json.decode(clientDataJSON);

    if (clientData['type'] != 'webauthn.create') {
      throw Exception('Invalid client data: type is not webauthn.create');
    }
    if (clientData['challenge'] != expectedChallenge) {
      throw Exception('Invalid client data: challenge mismatch');
    }

    final originUrl = Uri.parse(clientData['origin']);
    if (originUrl.host != config.rpId) {
      throw Exception(
          'Invalid client data: origin mismatch. Expected ${config.rpId} but got ${originUrl.host}');
    }

    // 2. Decode attestationObject and parse authenticatorData
    final attestationObject =
        cbor.decode(base64Url.decode(_padBase64(attestationObjectBase64)))
            as CborMap;
    final authDataBytes =
        (attestationObject[CborString('authData')] as CborBytes).bytes;
    final authData = AuthenticatorData.parse(Uint8List.fromList(authDataBytes));

    // 3. Verify authenticatorData
    // Verify rpIdHash
    final expectedRpIdHash = sha256.convert(utf8.encode(config.rpId)).bytes;
    if (authData.rpIdHash.length != expectedRpIdHash.length) {
      throw Exception(
          'Attestation verification failed: rpIdHash length mismatch.');
    }
    var rpIdMismatch = 0;
    for (var i = 0; i < authData.rpIdHash.length; i++) {
      rpIdMismatch |= authData.rpIdHash[i] ^ expectedRpIdHash[i];
    }
    if (rpIdMismatch != 0) {
      throw Exception('Attestation verification failed: rpIdHash mismatch.');
    }

    // Verify flags
    if (!authData.userPresent) {
      throw Exception(
          'Attestation verification failed: User Present flag not set.');
    }

    // For registration, attested credential data must be present.
    if (!authData.hasAttestedCredentialData ||
        authData.attestedCredentialData == null) {
      throw Exception(
          'Attestation verification failed: Attested Credential Data not included.');
    }

    final attestedData = authData.attestedCredentialData!;
    final credentialId = attestedData.credentialId;
    final credentialPublicKey = attestedData.credentialPublicKey;

    if (credentialId.length > 1023) {
      throw Exception(
          'Credential ID is too long (${credentialId.length} bytes). Max is 1023.');
    }

    // 4. Verify public key algorithm using supported algorithm list
    final coseMap =
        (credentialPublicKey.toObject() as Map).cast<int, dynamic>();
    final alg = coseMap[CoseKey.algIdx];
    if (!_supportedAlgorithms.contains(alg)) {
      throw Exception(
          'Unsupported or missing public key algorithm: $alg. Not found in supported list.');
    }

    // Note: The attestation statement (`attStmt`) is not verified here,
    // as we assume a simple 'none' attestation format for this implementation.

    return RegistrationResult(
      credentialId: credentialId,
      credentialPublicKey: credentialPublicKey,
    );
  }

  /// Completes verification (authentication assertion) using the caller-provided
  /// public key that was previously registered.
  ///
  /// Throws an exception if verification fails.
  Future<VerificationResult> completeVerification(
    String clientDataBase64,
    String authenticatorDataBase64,
    String signatureBase64,
    String expectedChallenge,
    CborMap credentialPublicKeyCbor,
    int storedSignCount,
  ) async {
    final credentialPublicKey = CoseKey.parse(
        (credentialPublicKeyCbor.toObject() as Map).cast<int, dynamic>());

    // 1. Decode and verify clientDataJSON
    final clientDataJSON =
        utf8.decode(base64Url.decode(_padBase64(clientDataBase64)));
    final clientData = json.decode(clientDataJSON);

    if (clientData['type'] != 'webauthn.get') {
      throw Exception('Invalid client data: type is not webauthn.get');
    }
    if (clientData['challenge'] != expectedChallenge) {
      throw Exception('Invalid client data: challenge mismatch');
    }

    final originUrl = Uri.parse(clientData['origin']);
    if (originUrl.host != config.rpId) {
      throw Exception(
          'Invalid client data: origin mismatch. Expected ${config.rpId} but got ${originUrl.host}');
    }

    // 2. Parse authenticatorData
    final authDataBytes = base64Url.decode(_padBase64(authenticatorDataBase64));
    final authData = AuthenticatorData.parse(Uint8List.fromList(authDataBytes));

    // Verify rpIdHash
    final expectedRpIdHash = sha256.convert(utf8.encode(config.rpId)).bytes;
    if (authData.rpIdHash.length != expectedRpIdHash.length) {
      throw Exception(
          'Assertion verification failed: rpIdHash length mismatch.');
    }
    var rpIdMismatch = 0;
    for (var i = 0; i < authData.rpIdHash.length; i++) {
      rpIdMismatch |= authData.rpIdHash[i] ^ expectedRpIdHash[i];
    }
    if (rpIdMismatch != 0) {
      throw Exception('Assertion verification failed: rpIdHash mismatch.');
    }

    // Flags must indicate user present
    if (!authData.userPresent) {
      throw Exception(
          'Assertion verification failed: User Present flag not set.');
    }

    // Verify sign count
    if (authData.signCount != 0 && storedSignCount != 0) {
      if (authData.signCount <= storedSignCount) {
        throw Exception(
            'Assertion verification failed: Authenticator sign count did not increase.');
      }
    }

    // 3. Verify signature over authData || SHA256(clientDataJSON)
    final clientDataHash = sha256.convert(utf8.encode(clientDataJSON)).bytes;
    final signedBytes =
        Uint8List.fromList([...authDataBytes, ...clientDataHash]);
    final signature = base64Url.decode(_padBase64(signatureBase64));

    await credentialPublicKey.verify(signedBytes, signature);

    return VerificationResult(
      userPresent: authData.userPresent,
      userVerified: authData.userVerified,
      signCount: authData.signCount,
      authenticatorData: Uint8List.fromList(authDataBytes),
    );
  }
}
