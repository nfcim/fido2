import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cbor/cbor.dart';
import 'package:crypto/crypto.dart';

import 'config.dart';
import 'entities/authenticator_data.dart';
import 'entities/registration_data.dart';
import 'entities/session_data.dart';

/// A stateless FIDO2/WebAuthn server implementation.
class WebAuthnServer {
  final WebAuthnConfig config;
  final Random _secureRandom = Random.secure();

  static const List<Map<String, dynamic>> _supportedPubKeyCredParams = [
    {'type': 'public-key', 'alg': -7}, // ES256
    {'type': 'public-key', 'alg': -257}, // RS256
    {'type': 'public-key', 'alg': -8}, // EdDSA (Ed25519)
  ];

  WebAuthnServer(this.config);

  /// Helper to add padding to base64url strings if missing.
  String _padBase64(String base64) {
    var padded = base64;
    switch (padded.length % 4) {
      case 2:
        padded += '==';
        break;
      case 3:
        padded += '=';
        break;
    }
    return padded;
  }

  /// Generates a cryptographically random challenge.
  Uint8List _generateChallenge() {
    final challenge = Uint8List(32);
    for (var i = 0; i < challenge.length; i++) {
      challenge[i] = _secureRandom.nextInt(256);
    }
    return challenge;
  }

  /// Creates a stateless, tamper-proof session token.
  /// The token contains the challenge and username, signed with the server secret.
  String _createStatelessSessionToken(Uint8List challenge, String username) {
    final sessionData = {
      'challenge': base64Url.encode(challenge),
      'username': username,
      'expires':
          DateTime.now().add(const Duration(minutes: 5)).toIso8601String(),
    };
    final sessionDataJson = json.encode(sessionData);
    final hmac = Hmac(sha256, config.rpSecret);
    final signature = hmac.convert(utf8.encode(sessionDataJson));

    final tokenPayload = base64Url.encode(utf8.encode(sessionDataJson));
    final tokenSignature = base64Url.encode(signature.bytes);

    return '$tokenPayload.$tokenSignature';
  }

  /// Verifies the stateless session token and decodes its content.
  /// Throws an exception if the token is invalid, tampered with, or expired.
  StatelessSessionData _verifyStatelessSessionToken(String token) {
    final parts = token.split('.');
    if (parts.length != 2) {
      throw Exception('Invalid session token format.');
    }
    final payloadBase64 = _padBase64(parts[0]);
    final signatureBase64 = _padBase64(parts[1]);

    final hmac = Hmac(sha256, config.rpSecret);
    final expectedSignature = hmac.convert(base64Url.decode(payloadBase64));
    final receivedSignature = base64Url.decode(signatureBase64);

    if (expectedSignature.bytes.length != receivedSignature.length) {
      throw Exception('Invalid signature.');
    }
    var mismatch = 0;
    for (var i = 0; i < expectedSignature.bytes.length; i++) {
      mismatch |= expectedSignature.bytes[i] ^ receivedSignature[i];
    }
    if (mismatch != 0) {
      throw Exception('Invalid signature.');
    }

    final sessionDataJson = utf8.decode(base64Url.decode(payloadBase64));
    final sessionData =
        StatelessSessionData.fromJson(json.decode(sessionDataJson));

    if (sessionData.expires.isBefore(DateTime.now())) {
      throw Exception('Session token expired.');
    }

    return sessionData;
  }

  /// Initiates a new user registration ceremony.
  RegistrationInitResponse initiateRegistration(
      String username, String displayName) {
    final challenge = _generateChallenge();
    final sessionToken = _createStatelessSessionToken(challenge, username);

    final options = {
      'rp': {'id': config.rpId, 'name': config.rpName},
      'user': {
        'id': base64Url.encode(utf8.encode(username)),
        'name': username,
        'displayName': displayName,
      },
      'challenge': base64Url.encode(challenge),
      'pubKeyCredParams': _supportedPubKeyCredParams,
      'timeout': 60000,
      'attestation': 'none',
    };

    return RegistrationInitResponse(
      creationOptions: options,
      sessionToken: sessionToken,
    );
  }

  /// Completes the registration ceremony by verifying the authenticator's response.
  ///
  /// Throws an exception if any part of the verification fails.
  /// Returns a [RegistrationResult] on success, which should be stored.
  RegistrationResult completeRegistration(
    String sessionToken,
    String clientDataBase64,
    String attestationObjectBase64,
  ) {
    final sessionData = _verifyStatelessSessionToken(sessionToken);

    // 1. Decode and verify clientDataJSON
    final clientDataJSON =
        utf8.decode(base64Url.decode(_padBase64(clientDataBase64)));
    final clientData = json.decode(clientDataJSON);

    if (clientData['type'] != 'webauthn.create') {
      throw Exception('Invalid client data: type is not webauthn.create');
    }
    if (clientData['challenge'] != sessionData.challenge) {
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

    // 4. Verify public key algorithm
    final pubKeyAlg = credentialPublicKey[CborInt(BigInt.from(3))]?.toObject();
    if (pubKeyAlg == null ||
        !_supportedPubKeyCredParams.any((param) => param['alg'] == pubKeyAlg)) {
      throw Exception(
          'Unsupported or missing public key algorithm: $pubKeyAlg. Not found in supported list.');
    }

    // Note: The attestation statement (`attStmt`) is not verified here,
    // as we assume a simple 'none' attestation format for this implementation.

    return RegistrationResult(
      credentialId: credentialId,
      credentialPublicKey: credentialPublicKey,
    );
  }
}
