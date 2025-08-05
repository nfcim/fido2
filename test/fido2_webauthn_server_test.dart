import 'dart:convert';

import 'package:cbor/cbor.dart';
import 'package:crypto/crypto.dart';
import 'package:fido2/src/server/base.dart';
import 'package:fido2/src/server/config.dart';
import 'package:fido2/src/server/entities/registration_data.dart';
import 'package:test/test.dart';

// Test vectors captured from a real session
// RP ID: webauthn.io
// User: inuFaith
const String _testChallenge =
    'vSs89kN6alufwsu_HMYV6ibM01-KXDtO8RM1AsuzlTZHyWeVP6fyAFNj9_u7hV-VG4SsBgD_CLpU7qBXnGyqgw';
const String _testClientDataBase64 =
    'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoidlNzODlrTjZhbHVmd3N1X0hNWVY2aWJNMDEtS1hEdE84Uk0xQXN1emxUWkh5V2VWUDZmeUFGTmo5X3U3aFYtVkc0U3NCZ0RfQ0xwVTdxQlhuR3lxZ3ciLCJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLmlvIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ';
const String _testAttestationObjectBase64 =
    'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVindKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBFAAAARwAAAAAAAAAAAAAAAAAAAAAARhAiATOz1GHiNEIjsroOJ56FlGOalgn3wGzu7zUMPCN3AQF0puqSE8mcL3SyJJKzIM9AJiqUwalQoDl_KSULYIQe8P____ikAQEDJyAGIVggoXSYysqAbT9NRyjGVhtiFS0A3ailhY28IiXxBRYmoYk';

void main() {
  group('WebAuthn Server', () {
    final config = WebAuthnConfig(
      rpId: 'webauthn.io',
      rpName: 'Webauthn.io Test',
      rpSecret:
          utf8.encode('a-very-secret-key-that-is-long-enough-for-hmac-sha256'),
    );
    final server = WebAuthnServer(config);

    String createTestSessionToken(String challenge, String username) {
      final sessionData = {
        'challenge': challenge,
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

    test('Normal', () {
      final sessionToken = createTestSessionToken(_testChallenge, 'inuFaith');

      final result = server.completeRegistration(
        sessionToken,
        _testClientDataBase64,
        _testAttestationObjectBase64,
      );

      expect(result, isA<RegistrationResult>());
      expect(result.credentialId, isNotEmpty);
      expect(result.credentialPublicKey, isA<CborMap>());

      final pubKey = result.credentialPublicKey;
      expect(pubKey[CborInt(BigInt.from(1))]?.toObject(),
          equals(1)); // Key type: OKP (Octet Key Pair)
      expect(pubKey[CborInt(BigInt.from(-1))]?.toObject(),
          equals(6)); // Curve: Ed25519
      expect(pubKey[CborInt(BigInt.from(3))]?.toObject(),
          equals(-8)); // Algorithm: EdDSA
    });

    test('Mismatched challenge', () {
      final sessionToken =
          createTestSessionToken('wrong-challenge-value', 'inuFaith');
      expect(
        () => server.completeRegistration(
            sessionToken, _testClientDataBase64, _testAttestationObjectBase64),
        throwsA(predicate((e) =>
            e is Exception && e.toString().contains('challenge mismatch'))),
      );
    });

    test('Mismatched origin/rpId', () {
      final badConfig = WebAuthnConfig(
          rpId: 'evil.com', rpName: 'Evil Corp', rpSecret: config.rpSecret);
      final badServer = WebAuthnServer(badConfig);
      final sessionToken = createTestSessionToken(_testChallenge, 'inuFaith');

      expect(
        () => badServer.completeRegistration(
            sessionToken, _testClientDataBase64, _testAttestationObjectBase64),
        throwsA(predicate(
            (e) => e is Exception && e.toString().contains('origin mismatch'))),
      );
    });
  });
}
