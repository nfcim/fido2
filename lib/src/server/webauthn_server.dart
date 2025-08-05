import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cbor/cbor.dart';
import 'package:crypto/crypto.dart';

/// Data parsed from the `attestedCredentialData` block of an `authenticatorData`
/// buffer. This contains the credential information.
class AttestedCredentialData {
  /// The AAGUID of the authenticator.
  final Uint8List aaguid;

  /// The credential ID.
  final Uint8List credentialId;

  /// The credential public key as a COSE_Key map.
  final CborMap credentialPublicKey;

  AttestedCredentialData({
    required this.aaguid,
    required this.credentialId,
    required this.credentialPublicKey,
  });
}

/// A structured representation of the `authenticatorData` buffer returned
/// by an authenticator.
///
/// It provides a safe way to parse and access the different fields of the
/// authenticator data.
class AuthenticatorData {
  /// The SHA-256 hash of the RP ID.
  final Uint8List rpIdHash;

  /// The flags byte.
  final int flags;

  /// The signature counter.
  final int signCount;

  /// The attested credential data, if present.
  final AttestedCredentialData? attestedCredentialData;

  /// Authenticator extension outputs, if present.
  final CborMap? extensions;

  AuthenticatorData({
    required this.rpIdHash,
    required this.flags,
    required this.signCount,
    this.attestedCredentialData,
    this.extensions,
  });

  /// User Present flag (bit 0).
  bool get userPresent => (flags & 0x01) != 0;

  /// User Verified flag (bit 2).
  bool get userVerified => (flags & 0x04) != 0;

  /// Attested Credential Data included flag (bit 6).
  bool get hasAttestedCredentialData => (flags & 0x40) != 0;

  /// Extension data included flag (bit 7).
  bool get hasExtensions => (flags & 0x80) != 0;

  /// Parses the raw authenticator data buffer into a structured object.
  ///
  /// This follows the structure defined in the WebAuthn specification:
  /// https://www.w3.org/TR/webauthn-2/#sctn-authenticator-data
  static AuthenticatorData parse(Uint8List authDataBytes) {
    var offset = 0;

    // Helper to read a chunk of bytes and advance the offset.
    Uint8List readBytes(int length) {
      if (authDataBytes.length < offset + length) {
        throw Exception(
          'Authenticator data too short. Needed $length bytes at offset $offset, but length is ${authDataBytes.length}',
        );
      }
      final slice = authDataBytes.sublist(offset, offset + length);
      offset += length;
      return slice;
    }

    final rpIdHash = readBytes(32);
    final flags = readBytes(1)[0];
    final signCountBytes = readBytes(4);
    final signCount = ByteData.view(
      signCountBytes.buffer,
      signCountBytes.offsetInBytes,
    ).getUint32(0, Endian.big);

    AttestedCredentialData? attestedCredentialData;
    CborMap? extensions;

    final hasAttestedData = (flags & 0x40) != 0;
    final hasExtensions = (flags & 0x80) != 0;

    if (hasAttestedData) {
      final aaguid = readBytes(16);
      final credIdLengthBytes = readBytes(2);
      final credentialIdLength = ByteData.view(
        credIdLengthBytes.buffer,
        credIdLengthBytes.offsetInBytes,
      ).getUint16(0, Endian.big);
      final credentialId = readBytes(credentialIdLength);

      // The rest of the buffer is the CBOR-encoded public key and, if present, extensions.
      final remainingBytes = authDataBytes.sublist(offset);
      if (remainingBytes.isEmpty) {
        throw Exception(
            'Authenticator data ended unexpectedly. Missing credential public key.');
      }

      // cbor.decode() can return a CborList if multiple items are in the buffer,
      // or a single CborValue if only one is present. We need to handle both cases.
      final decodedValues = cbor.decode(remainingBytes);

      final CborMap credentialPublicKey;
      final List<CborValue> items;
      if (decodedValues is CborList) {
        items = decodedValues;
      } else {
        items = [decodedValues];
      }

      if (items.isEmpty || items.first is! CborMap) {
        throw Exception(
            'Could not parse credential public key, expected a CborMap.');
      }
      credentialPublicKey = items.first as CborMap;

      // Manually calculate how many bytes the public key consumed.
      final pkBytes = cbor.encode(credentialPublicKey);
      offset += pkBytes.length;

      attestedCredentialData = AttestedCredentialData(
        aaguid: aaguid,
        credentialId: credentialId,
        credentialPublicKey: credentialPublicKey,
      );
    }

    if (hasExtensions) {
      // Extensions are located after the attested credential data (if any).
      if (authDataBytes.length > offset) {
        final extBytes = authDataBytes.sublist(offset);
        if (extBytes.isNotEmpty) {
          final decodedExt = cbor.decode(extBytes);
          if (decodedExt is CborMap) {
            extensions = decodedExt;
          }
        }
      }
    }

    return AuthenticatorData(
      rpIdHash: rpIdHash,
      flags: flags,
      signCount: signCount,
      attestedCredentialData: attestedCredentialData,
      extensions: extensions,
    );
  }
}

/// Configuration for the WebAuthn server.
class WebAuthnConfig {
  /// The ID of the Relying Party. Typically the domain of your web service.
  final String rpId;

  /// The human-readable name of the Relying Party.
  final String rpName;

  /// A secret key known only to the server, used to sign stateless session data.
  /// This MUST be kept secret and should be a long, random string.
  final List<int> rpSecret;

  WebAuthnConfig({
    required this.rpId,
    required this.rpName,
    required this.rpSecret,
  });
}

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

/// Data decoded from a verified stateless session token.
class StatelessSessionData {
  final String challenge; // Stored as base64url
  final String username;
  final DateTime expires;

  StatelessSessionData({
    required this.challenge,
    required this.username,
    required this.expires,
  });

  factory StatelessSessionData.fromJson(Map<String, dynamic> json) {
    return StatelessSessionData(
      challenge: json['challenge'],
      username: json['username'],
      expires: DateTime.parse(json['expires']),
    );
  }
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
