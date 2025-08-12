import 'dart:convert';

import 'package:cbor/cbor.dart';
import 'package:fido2/src/server/base.dart';
import 'package:fido2/src/server/config.dart';
import 'package:fido2/src/server/entities/registration_data.dart';
import 'package:fido2/src/server/session.dart';
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
    );

    final sessionStore = InMemorySessionStore();
    final server = WebAuthnServer(config, sessionStore);

    setUp(() {
      sessionStore.clear();
    });

    test('Normal registration completion', () async {
      const sessionId = 'test-session-id';
      final sessionData = SessionData(
        challenge: _testChallenge,
        username: 'inuFaith',
        expires: DateTime.now().add(const Duration(minutes: 5)),
      );
      await sessionStore.save(sessionId, sessionData);

      final result = await server.completeRegistration(
        sessionId,
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

    test('Mismatched challenge', () async {
      const sessionId = 'test-session-id-mismatch-challenge';
      // The session is stored with a different challenge
      final sessionData = SessionData(
        challenge: 'wrong-challenge-value',
        username: 'inuFaith',
        expires: DateTime.now().add(const Duration(minutes: 5)),
      );
      await sessionStore.save(sessionId, sessionData);

      // But the client data contains the _testChallenge
      expect(
        () => server.completeRegistration(
            sessionId, _testClientDataBase64, _testAttestationObjectBase64),
        throwsA(predicate((e) =>
            e is Exception && e.toString().contains('challenge mismatch'))),
      );
    });

    test('Mismatched origin/rpId', () async {
      final badConfig = WebAuthnConfig(
        rpId: 'evil.com',
        rpName: 'Evil Corp',
      );
      final badServer = WebAuthnServer(badConfig, sessionStore);
      const sessionId = 'test-session-id-mismatch-origin';

      final sessionData = SessionData(
        challenge: _testChallenge,
        username: 'inuFaith',
        expires: DateTime.now().add(const Duration(minutes: 5)),
      );
      await sessionStore.save(sessionId, sessionData);

      expect(
        () => badServer.completeRegistration(
            sessionId, _testClientDataBase64, _testAttestationObjectBase64),
        throwsA(predicate(
            (e) => e is Exception && e.toString().contains('origin mismatch'))),
      );
    });

    test('Session not found', () {
      const sessionId = 'non-existent-session-id';
      expect(
        () => server.completeRegistration(
            sessionId, _testClientDataBase64, _testAttestationObjectBase64),
        throwsA(predicate((e) =>
            e is Exception && e.toString().contains('Session not found'))),
      );
    });

    test('Full registration flow', () async {
      // 1. Initiate registration
      final initResponse =
          await server.initiateRegistration('testuser', 'Test User');
      final sessionId = initResponse.sessionId;
      final challenge = initResponse.creationOptions['challenge'] as String;

      final session = await sessionStore.load(sessionId);
      expect(session, isNotNull);
      expect(session!.challenge, equals(challenge));

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
      final result = await server.completeRegistration(
        sessionId,
        clientDataBase64,
        _testAttestationObjectBase64,
      );

      // 3. Verify success
      expect(result, isA<RegistrationResult>());
      expect(result.credentialId, isNotEmpty);

      // Verify session was deleted after successful completion
      final deletedSession = await sessionStore.load(sessionId);
      expect(deletedSession, isNull);
    });
  });
}
