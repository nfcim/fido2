import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cbor/cbor.dart';
import 'package:crypto/crypto.dart';

import 'config.dart';
import 'entities/authenticator_data.dart';
import 'entities/registration_data.dart';
import 'session.dart';

/// A stateful FIDO2/WebAuthn server implementation.
class WebAuthnServer {
  final WebAuthnConfig config;
  final Random _secureRandom = Random.secure();
  final SessionStore _sessionStore;

  static const List<Map<String, dynamic>> _supportedPubKeyCredParams = [
    {'type': 'public-key', 'alg': -7}, // ES256
    {'type': 'public-key', 'alg': -257}, // RS256
    {'type': 'public-key', 'alg': -8}, // EdDSA (Ed25519)
  ];

  WebAuthnServer(this.config, this._sessionStore);

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

  // No stateless token helpers in the stateful server.

  /// Initiates a new user registration ceremony.
  Future<RegistrationInitResponse> initiateRegistration(
      String username, String displayName) async {
    final challenge = _generateChallenge();
    // Create a session id and persist the challenge statefully.
    final sessionId = base64Url.encode(_generateChallenge());
    final sessionData = SessionData(
      challenge: base64Url.encode(challenge),
      username: username,
      expires: DateTime.now().add(const Duration(minutes: 5)),
    );
    await _sessionStore.save(sessionId, sessionData);

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
    );
  }

  /// Completes the registration ceremony by verifying the authenticator's response.
  ///
  /// Throws an exception if any part of the verification fails.
  /// Returns a [RegistrationResult] on success, which should be stored.
  Future<RegistrationResult> completeRegistration(
    String sessionId,
    String clientDataBase64,
    String attestationObjectBase64,
  ) async {
    final sessionData = await _sessionStore.load(sessionId);
    if (sessionData == null) {
      throw Exception('Session not found');
    }
    if (sessionData.expires.isBefore(DateTime.now())) {
      throw Exception('Session expired');
    }

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
    await _sessionStore.delete(sessionId);

    return RegistrationResult(
      credentialId: credentialId,
      credentialPublicKey: credentialPublicKey,
    );
  }
}
