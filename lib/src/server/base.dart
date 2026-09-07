import 'dart:convert';
import 'package:cbor/cbor.dart';
import 'dart:typed_data';
import 'entities/authenticator_data.dart';
import 'entities/registration_data.dart';
import 'entities/verification_data.dart';
import '../cose.dart';
import '../crypto/crypto.dart';
import '../ctap2/entities/credential_entities.dart';
import 'config.dart';
import '../strict_cbor.dart';

String _b64(List<int> bytes) => base64Url.encode(bytes).replaceAll('=', '');
List<int> _decode(Object? value) {
  if (value is! String ||
      value.length > 350000 ||
      !RegExp(r'^[A-Za-z0-9_-]*={0,2}$').hasMatch(value)) {
    throw const FormatException('Expected base64url bytes');
  }
  return base64Url.decode(base64Url.normalize(value));
}

/// WebAuthn server ceremonies. Callers must store challenges server-side,
/// bind them to the user/session, expire them, and atomically consume them once.
/// Registration supports fmt=none and validates the credential public key.
class Fido2Server {
  final Fido2Config config;
  Fido2Server(this.config);

  RegistrationRequest registerBegin(
    PublicKeyCredentialUserEntity user, {
    List<int>? challenge,
  }) {
    final nonce = List<int>.unmodifiable(
      challenge ?? RustCrypto.randomBytes(32),
    );
    if (nonce.length < 16) {
      throw ArgumentError('Challenge must be at least 16 bytes');
    }
    final offered = List<int>.unmodifiable(config.signatureAlgorithms);
    return RegistrationRequest(
      {
        'rp': {'id': config.rpId, 'name': config.rpName},
        'user': {
          'id': _b64(user.id),
          'name': user.name,
          'displayName': user.displayName,
        },
        'challenge': _b64(nonce),
        'pubKeyCredParams': [
          for (final alg in offered) {'type': 'public-key', 'alg': alg},
        ],
        'attestation': 'none',
        'authenticatorSelection': {
          'userVerification': config.requireUserVerification
              ? 'required'
              : 'preferred',
        },
      },
      nonce,
      offered,
    );
  }

  Map<String, dynamic> authenticateBegin({
    List<RegisteredCredential> credentials = const [],
    List<int>? challenge,
  }) {
    final nonce = challenge ?? RustCrypto.randomBytes(32);
    if (nonce.length < 16) {
      throw ArgumentError('Challenge must be at least 16 bytes');
    }
    return {
      'challenge': _b64(nonce),
      'rpId': config.rpId,
      'allowCredentials': [
        for (final credential in credentials)
          {'type': 'public-key', 'id': _b64(credential.id)},
      ],
      'userVerification': config.requireUserVerification
          ? 'required'
          : 'preferred',
    };
  }

  Map<String, dynamic> _response(Map<String, dynamic> credential) {
    if (credential['type'] != 'public-key' || credential['response'] is! Map) {
      throw const FormatException('Expected public-key credential response');
    }
    final id = _decode(credential['rawId']);
    if (!RustCrypto.constantTimeEquals(id, _decode(credential['id']))) {
      throw const FormatException('Credential id/rawId mismatch');
    }
    return Map<String, dynamic>.from(credential['response'] as Map);
  }

  List<int> _clientData(Object? encoded, String type, List<int> challenge) {
    if (challenge.length < 16) {
      throw ArgumentError('Challenge must be at least 16 bytes');
    }
    final bytes = _decode(encoded);
    final value = jsonDecode(utf8.decode(bytes));
    if (value is! Map ||
        value['type'] != type ||
        !config.origins.contains(value['origin']) ||
        (value.containsKey('crossOrigin') && value['crossOrigin'] != false) ||
        !RustCrypto.constantTimeEquals(
          _decode(value['challenge']),
          challenge,
        )) {
      throw const FormatException(
        'Invalid client data type, origin, or challenge',
      );
    }
    return bytes;
  }

  void _authenticator(AuthenticatorData data) {
    if (!RustCrypto.constantTimeEquals(
          data.rpIdHash,
          RustCrypto.sha256(utf8.encode(config.rpId)),
        ) ||
        !data.userPresent ||
        (config.requireUserVerification && !data.userVerified)) {
      throw const FormatException(
        'Invalid RP hash or user presence/verification flags',
      );
    }
  }

  /// Completes registration using the saved request's [offeredAlgorithms] and
  /// account ID ([userHandle]). Returns the credential and initial backup state.
  RegisteredCredential registerComplete(
    Map<String, dynamic> credential, {
    required List<int> expectedChallenge,
    List<int>? offeredAlgorithms,
    List<int>? userHandle,
  }) {
    final response = _response(credential);
    final registered = _registerResponse(
      response,
      expectedChallenge: expectedChallenge,
      offeredAlgorithms: offeredAlgorithms,
      userHandle: userHandle,
    );
    if (!RustCrypto.constantTimeEquals(
      registered.id,
      _decode(credential['rawId']),
    )) {
      throw const FormatException('Mismatched credential ID');
    }
    return registered;
  }

  RegisteredCredential _registerResponse(
    Map<String, dynamic> response, {
    required List<int> expectedChallenge,
    List<int>? offeredAlgorithms,
    List<int>? userHandle,
  }) {
    _clientData(
      response['clientDataJSON'],
      'webauthn.create',
      expectedChallenge,
    );
    final object = decodeStrictCbor(_decode(response['attestationObject']));
    if (object is! CborMap ||
        object.tags.isNotEmpty ||
        object[CborString('fmt')] != CborString('none') ||
        object[CborString('attStmt')] is! CborMap ||
        (object[CborString('attStmt')] as CborMap).isNotEmpty) {
      throw UnsupportedError(
        'Only none attestation is supported; attestation trust is not verified',
      );
    }
    final encodedData = object[CborString('authData')];
    if (encodedData is! CborBytes) {
      throw const FormatException('Expected authData bytes');
    }
    final data = AuthenticatorData.parse(
      encodedData.bytes,
      configuration: config.cose,
    );
    _authenticator(data);
    final key = data.credentialPublicKey;
    if (key == null || data.credentialId == null) {
      throw const FormatException('Missing or mismatched attested credential');
    }
    // Check the saved request list and the current policy.
    if (!(offeredAlgorithms ?? config.signatureAlgorithms).contains(
          key.algorithmId,
        ) ||
        !config.signatureAlgorithms.contains(key.algorithmId) ||
        config.cose.resolve(key.algorithmId) == null) {
      throw const FormatException(
        'Credential algorithm was not requested or is not allowed',
      );
    }
    key.validate();
    return RegisteredCredential(
      id: data.credentialId!,
      publicKey: key,
      signCount: data.signCount,
      backupEligible: data.backupEligible,
      backedUp: data.backedUp,
      userHandle: userHandle,
    );
  }

  /// Returns the new sign counter after successful assertion verification.
  int authenticateComplete(
    Map<String, dynamic> assertion, {
    required RegisteredCredential credential,
    required List<int> expectedChallenge,
    List<int>? expectedUserHandle,
    bool requireUserHandle = false,
  }) => authenticateCompleteResult(
    assertion,
    credential: credential,
    expectedChallenge: expectedChallenge,
    expectedUserHandle: expectedUserHandle,
    requireUserHandle: requireUserHandle,
  ).signCount;

  /// Persist both fields only after this method succeeds. BS may change in
  /// either direction. For usernameless login, require a returned user handle
  /// and resolve the credential and expected handle from the same account.
  AuthenticationResult authenticateCompleteResult(
    Map<String, dynamic> assertion, {
    required RegisteredCredential credential,
    required List<int> expectedChallenge,
    List<int>? expectedUserHandle,
    bool requireUserHandle = false,
  }) {
    final response = _response(assertion);
    if (!RustCrypto.constantTimeEquals(
      _decode(assertion['rawId']),
      credential.id,
    )) {
      throw const FormatException('Unexpected credential');
    }
    return _authenticateResponse(
      response,
      publicKey: credential.publicKey,
      storedSignCount: credential.signCount,
      storedBackupEligible: credential.backupEligible,
      storedUserHandle: credential.userHandle,
      expectedChallenge: expectedChallenge,
      expectedUserHandle: expectedUserHandle,
      requireUserHandle: requireUserHandle,
    );
  }

  AuthenticationResult _authenticateResponse(
    Map<String, dynamic> response, {
    required CoseKey publicKey,
    required int storedSignCount,
    bool? storedBackupEligible,
    List<int>? storedUserHandle,
    required List<int> expectedChallenge,
    List<int>? expectedUserHandle,
    bool requireUserHandle = false,
  }) {
    final expected = expectedUserHandle ?? storedUserHandle;
    if (expectedUserHandle != null &&
        storedUserHandle != null &&
        !RustCrypto.constantTimeEquals(expectedUserHandle, storedUserHandle)) {
      throw const FormatException('Conflicting expected user handles');
    }
    if (expected != null &&
        (expected.isEmpty ||
            expected.length > 64 ||
            expected.any((b) => b < 0 || b > 255))) {
      throw ArgumentError('User handle must contain 1 to 64 bytes');
    }
    final returnedHandle = response['userHandle'];
    if (returnedHandle != null) {
      if (expected == null ||
          !RustCrypto.constantTimeEquals(_decode(returnedHandle), expected)) {
        throw const FormatException('Unexpected or unbound user handle');
      }
    } else if (requireUserHandle) {
      throw const FormatException('User handle required');
    }
    final clientData = _clientData(
      response['clientDataJSON'],
      'webauthn.get',
      expectedChallenge,
    );
    final data = AuthenticatorData.parse(
      _decode(response['authenticatorData']),
      configuration: config.cose,
    );
    _authenticator(data);
    if (data.credentialPublicKey != null ||
        (storedBackupEligible != null &&
            data.backupEligible != storedBackupEligible)) {
      throw const FormatException('Invalid assertion flags');
    }
    final algorithm = publicKey.algorithmId;
    if (!config.signatureAlgorithms.contains(algorithm) ||
        config.cose.resolve(algorithm) == null) {
      throw UnsupportedError('Credential signature algorithm is not allowed');
    }
    // Reparse persisted keys with this server's trusted profile and algorithm mapping.
    final key = CoseKey.fromCborMap(
      publicKey.toCborMap(),
      configuration: config.cose,
    );
    key.verifySync([
      ...data.bytes,
      ...RustCrypto.sha256(clientData),
    ], _decode(response['signature']));
    if ((storedSignCount != 0 || data.signCount != 0) &&
        data.signCount <= storedSignCount) {
      throw const FormatException('Signature counter did not increase');
    }
    return AuthenticationResult(
      signCount: data.signCount,
      backedUp: data.backedUp,
    );
  }

  Map<String, dynamic> generateRegistrationOptions(
    String username,
    String displayName, {
    List<int>? userHandle,
  }) {
    final options = registerBegin(
      PublicKeyCredentialUserEntity(
        id: userHandle ?? utf8.encode(username),
        name: username,
        displayName: displayName,
      ),
    ).publicKey;
    return {...options, 'timeout': 60000};
  }

  Map<String, dynamic> generateVerificationOptions() => {
    ...authenticateBegin(),
    'timeout': 60000,
  };

  RegistrationResult completeRegistration(
    String clientDataBase64,
    String attestationObjectBase64,
    String expectedChallenge, {
    List<int>? offeredAlgorithms,
    List<int>? userHandle,
  }) {
    final stored = _registerResponse(
      {
        'clientDataJSON': clientDataBase64,
        'attestationObject': attestationObjectBase64,
      },
      expectedChallenge: _decode(expectedChallenge),
      offeredAlgorithms: offeredAlgorithms,
      userHandle: userHandle,
    );
    return RegistrationResult(
      credentialId: Uint8List.fromList(stored.id),
      credentialPublicKey: stored.publicKey.toCborMap(),
      signCount: stored.signCount,
      backupEligible: stored.backupEligible,
      backedUp: stored.backedUp,
      userHandle: stored.userHandle,
    );
  }

  Future<VerificationResult> completeVerification(
    String clientDataBase64,
    String authenticatorDataBase64,
    String signatureBase64,
    String expectedChallenge,
    CborMap credentialPublicKeyCbor,
    int storedSignCount, {
    String? userHandle,
    List<int>? expectedUserHandle,
    bool requireUserHandle = false,
    bool? storedBackupEligible,
  }) async {
    final key = CoseKey.fromCborMap(
      credentialPublicKeyCbor,
      configuration: config.cose,
    );
    final result = _authenticateResponse(
      {
        'clientDataJSON': clientDataBase64,
        'authenticatorData': authenticatorDataBase64,
        'signature': signatureBase64,
        'userHandle': userHandle,
      },
      publicKey: key,
      storedSignCount: storedSignCount,
      storedBackupEligible: storedBackupEligible,
      expectedChallenge: _decode(expectedChallenge),
      expectedUserHandle: expectedUserHandle,
      requireUserHandle: requireUserHandle,
    );
    final bytes = Uint8List.fromList(_decode(authenticatorDataBase64));
    return VerificationResult(
      userPresent: bytes[32] & 1 != 0,
      userVerified: bytes[32] & 4 != 0,
      signCount: result.signCount,
      authenticatorData: bytes,
      backupEligible: bytes[32] & 8 != 0,
      backedUp: result.backedUp,
    );
  }
}
