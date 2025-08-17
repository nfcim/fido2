import 'dart:convert';

import 'package:cbor/cbor.dart';
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
  group('Fido2Server', () {
    final config = Fido2Config(
      rpId: 'webauthn.io',
      rpName: 'Webauthn.io Test',
    );

    final server = Fido2Server(config);

    test('Normal registration completion', () {
      final result = server.completeRegistration(
        _testClientDataBase64,
        _testAttestationObjectBase64,
        _testChallenge, // The RP server would have stored this
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
      const wrongChallenge = 'wrong-challenge-value';
      expect(
        () => server.completeRegistration(
          _testClientDataBase64,
          _testAttestationObjectBase64,
          wrongChallenge,
        ),
        throwsA(predicate((e) =>
            e is Exception && e.toString().contains('challenge mismatch'))),
      );
    });

    test('Mismatched origin/rpId', () {
      final badConfig = Fido2Config(
        rpId: 'evil.com',
        rpName: 'Evil Corp',
      );
      final badServer = Fido2Server(badConfig);

      expect(
        () => badServer.completeRegistration(
          _testClientDataBase64,
          _testAttestationObjectBase64,
          _testChallenge,
        ),
        throwsA(predicate(
            (e) => e is Exception && e.toString().contains('origin mismatch'))),
      );
    });

    test('Full registration flow', () {
      // 1. RP server generates registration options
      final options =
          server.generateRegistrationOptions('testuser', 'Test User');
      final challenge = options['challenge'] as String;

      // RP server would now store the challenge and send options to the client.

      // 2. Simulate client response and complete registration
      // Build a clientDataJSON with the dynamic challenge from step 1.
      final clientDataMap = {
        'type': 'webauthn.create',
        'challenge': challenge,
        'origin': 'https://webauthn.io',
        'crossOrigin': false,
      };
      final clientDataBase64 =
          base64Url.encode(utf8.encode(json.encode(clientDataMap)));

      // Reuse the static attestationObject since its rpIdHash matches the config
      // and it doesn't contain the challenge.
      final result = server.completeRegistration(
        clientDataBase64,
        _testAttestationObjectBase64,
        challenge, // RP server provides the stored challenge
      );

      // 3. Verify success
      expect(result, isA<RegistrationResult>());
      expect(result.credentialId, isNotEmpty);
    });
  });
}
