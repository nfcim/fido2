import 'dart:convert';
import 'package:cbor/cbor.dart';
import 'package:fido2/fido2.dart';
import 'package:test/test.dart';
import 'fixtures/fixtures.dart';
import 'support.dart';

List<int> bytes(Object? v) => (v as List).cast<int>();
String b64(List<int> v) => base64Url.encode(v).replaceAll('=', '');
final cose =
    CoseConfiguration(sm2: Sm2Configuration(algorithm: -65537, curve: -65537));
CoseKey keyFor(Map vector) {
  final key = bytes(vector['key']);
  return CoseKey.parse(
      switch (vector['algorithm']) {
        'es256' || 'sm2' => {
            1: 2,
            3: vector['alg'],
            -1: vector['algorithm'] == 'sm2' ? -65537 : 1,
            -2: key.sublist(1, 33),
            -3: key.sublist(33)
          },
        'ed25519' => {1: 1, 3: vector['alg'], -1: 6, -2: key},
        _ => {1: 7, 3: vector['alg'], -1: key},
      },
      configuration: cose);
}

void main() {
  setUpAll(initializeCrypto);
  final data = (jsonDecode(fixtureJson) as Map)['webauthn'] as Map;
  final challenge = bytes(data['challenge']);
  final auth = bytes(data['authenticatorData']);
  final id = [1, 2, 3];
  Fido2Server server(List<int> algorithms) => Fido2Server(Fido2Config(
      rpId: 'example.com',
      origins: {'https://example.com'},
      cose: cose,
      signatureAlgorithms: algorithms));
  List<int> registrationData(CoseKey key, {bool extensions = false}) => [
        ...auth.sublist(0, 32),
        extensions ? 0xc1 : 0x41,
        0,
        0,
        0,
        0,
        ...List.filled(16, 0),
        0,
        id.length,
        ...id,
        ...cbor.encode(key.toCbor()),
        if (extensions)
          ...cbor.encode(CborValue({
            'credProps': {'rk': true}
          })),
      ];
  Map<String, dynamic> registration(CoseKey key) => {
        'id': b64(id),
        'rawId': b64(id),
        'type': 'public-key',
        'response': {
          'clientDataJSON': b64(utf8.encode(jsonEncode({
            'type': 'webauthn.create',
            'challenge': b64(challenge),
            'origin': 'https://example.com'
          }))),
          'attestationObject': b64(cbor.encode(CborValue({
            'fmt': 'none',
            'attStmt': <String, dynamic>{},
            'authData': CborBytes(registrationData(key, extensions: true))
          })))
        }
      };
  Map<String, dynamic> assertion(Map vector) => {
        'id': b64(id),
        'rawId': b64(id),
        'type': 'public-key',
        'response': <String, dynamic>{
          'clientDataJSON': b64(bytes(data['clientDataJSON'])),
          'authenticatorData': b64(auth),
          'signature': b64(bytes(vector['signature']))
        }
      };

  test('default, single algorithm and mixed registration ordering', () {
    expect(
        Fido2Config(rpId: 'example.com', origins: {'https://example.com'})
            .signatureAlgorithms,
        [-7, -8]);
    for (final order in [
      [-65537],
      [-48],
      [-49],
      [-50],
      [-50, -65537, -8, -7, -48]
    ]) {
      final request = server(order).registerBegin(PublicKeyCredentialUserEntity(
          id: [1], name: 'user', displayName: 'User'));
      expect(request.offeredAlgorithms, order);
      expect(
          (request.publicKey['pubKeyCredParams'] as List).map((e) => e['alg']),
          order);
      expect(request.challenge, hasLength(32));
    }
    expect(() => server([-25]), throwsArgumentError);
    expect(() => server([-7, -7]), throwsArgumentError);
  });
  test('registration rejects duplicate attestation object fields', () {
    final vector = (data['vectors'] as List).first as Map;
    final response = registration(keyFor(vector));
    final entry = cbor.encode(CborValue('fmt'));
    (response['response'] as Map)['attestationObject'] = b64([
      0xa2,
      ...entry,
      ...cbor.encode(CborValue('none')),
      ...entry,
      ...cbor.encode(CborValue('none')),
    ]);
    expect(
        () => server([vector['alg'] as int])
            .registerComplete(response, expectedChallenge: challenge),
        throwsFormatException);
  });
  for (final vector in data['vectors'] as List) {
    final key = keyFor(vector as Map);
    final alg = vector['alg'] as int;
    group('${vector['algorithm']} full ceremony', () {
      test('register and authenticate with account binding', () {
        final s = server([alg]);
        final stored = s.registerComplete(registration(key),
            expectedChallenge: challenge,
            offeredAlgorithms: [alg],
            userHandle: [42]);
        final response = assertion(vector);
        (response['response'] as Map)['userHandle'] = b64([42]);
        expect(stored.publicKey.algorithmId, alg);
        expect(
            s.authenticateComplete(response,
                credential: stored,
                expectedChallenge: challenge,
                requireUserHandle: true),
            1);
      });
      test('reject unrequested/disabled algorithm and altered client data', () {
        final s = server([alg]);
        expect(
            () => s.registerComplete(registration(key),
                expectedChallenge: challenge, offeredAlgorithms: []),
            throwsFormatException);
        final stored = RegisteredCredential(id: id, publicKey: key);
        expect(
            () => server([alg == -7 ? -8 : -7]).authenticateComplete(
                assertion(vector),
                credential: stored,
                expectedChallenge: challenge),
            throwsUnsupportedError);
        final changed = assertion(vector);
        (changed['response'] as Map)['clientDataJSON'] =
            b64(utf8.encode(jsonEncode({
          'type': 'webauthn.get',
          'challenge': b64(challenge),
          'origin': 'https://example.com',
          'extra': true
        })));
        expect(
            () => s.authenticateComplete(changed,
                credential: stored, expectedChallenge: challenge),
            throwsA(isA<CryptoException>()));
        expect(
            () => s.authenticateComplete(assertion(vector),
                credential: stored, expectedChallenge: List.filled(32, 0)),
            throwsFormatException);
        expect(
            () => s.authenticateComplete(assertion(vector),
                credential:
                    RegisteredCredential(id: id, publicKey: key, signCount: 1),
                expectedChallenge: challenge),
            throwsFormatException);
      });
      test('COSE roundtrip and adjacent extension CBOR', () {
        final wire = cbor.encode(key.toCborMap());
        final parsed = CoseKey.fromCborMap(cbor.decode(wire) as CborMap,
            configuration: cose);
        expect(cbor.encode(parsed.toCborMap()), wire);
        for (final extensions in [false, true]) {
          final bytes = registrationData(key, extensions: extensions);
          final decoded = AuthenticatorData.parse(bytes, configuration: cose);
          expect(
              decoded.credentialPublicKey!.publicKeyBytes, key.publicKeyBytes);
          expect(decoded.extensions != null, extensions);
          expect(
              () => AuthenticatorData.parse(bytes.sublist(0, bytes.length - 1),
                  configuration: cose),
              throwsFormatException);
          expect(
              () => AuthenticatorData.parse([...bytes, 0], configuration: cose),
              throwsFormatException);
        }
      });
    });
  }
  test('trusted user handle binding and verified result', () {
    final vector = (data['vectors'] as List).first as Map;
    final key = keyFor(vector);
    final s = server([vector['alg'] as int]);
    final stored = s.registerComplete(registration(key),
        expectedChallenge: challenge, userHandle: [42]);
    expect(stored.userHandle, [42]);
    expect(stored.backedUp, isFalse);
    final response = assertion(vector);
    (response['response'] as Map)['userHandle'] = b64([42]);
    final result = s.authenticateCompleteResult(response,
        credential: stored,
        expectedChallenge: challenge,
        requireUserHandle: true);
    expect(result.signCount, 1);
    expect(result.backedUp, isFalse);
    expect(
        () => s.authenticateComplete(response,
            credential: stored,
            expectedChallenge: challenge,
            expectedUserHandle: [43]),
        throwsFormatException);
    final legacy = RegisteredCredential(id: id, publicKey: key);
    expect(
        () => s.authenticateComplete(response,
            credential: legacy, expectedChallenge: challenge),
        throwsFormatException);
    expect(
        s.authenticateComplete(response,
            credential: legacy,
            expectedChallenge: challenge,
            expectedUserHandle: [42]),
        1);
    for (final handle in [
      b64([43]),
      '',
      42,
      '***'
    ]) {
      (response['response'] as Map)['userHandle'] = handle;
      expect(
          () => s.authenticateComplete(response,
              credential: stored, expectedChallenge: challenge),
          throwsFormatException);
    }
    (response['response'] as Map)['userHandle'] = null;
    expect(
        s.authenticateComplete(response,
            credential: stored, expectedChallenge: challenge),
        1);
    expect(
        () => s.authenticateComplete(response,
            credential: stored,
            expectedChallenge: challenge,
            requireUserHandle: true),
        throwsFormatException);
  });
  test('unknown COSE fields retain CBOR types and unknown verifier rejects',
      () {
    final wire = CborMap({
      CborSmallInt(1): CborSmallInt(99),
      CborSmallInt(3): CborSmallInt(-60000),
      CborSmallInt(-1): CborBytes([1, 2], tags: [100]),
      CborSmallInt(42): CborList([CborSmallInt(1), CborSmallInt(2)]),
      CborSmallInt(43): CborString('unknown', tags: [100])
    });
    final key = CoseKey.fromCborMap(wire);
    expect(key, isA<UnsupportedKey>());
    expect(cbor.encode(key.toCborMap()), cbor.encode(wire));
    expect(() => key.verify([], []), throwsUnsupportedError);
  });
  test('invalid key fields, lengths, mutation and parameter mismatch', () {
    expect(
        () => Sm2Configuration(algorithm: -54, curve: 9), throwsArgumentError);
    final deployed = Sm2Configuration(
        algorithm: -54, curve: 9, allowUnassignedIdentifiers: true);
    expect(
        CoseConfiguration(sm2: deployed).resolve(-54), SignatureAlgorithm.sm2);
    expect(
        () => Sm2Configuration(
            algorithm: -49, curve: 9, allowUnassignedIdentifiers: true),
        throwsArgumentError);
    expect(
        () => Sm2Configuration(
            algorithm: -54, curve: 1, allowUnassignedIdentifiers: true),
        throwsArgumentError);
    expect(
        () => MLDSA44.fromPublicKey(List.filled(1952, 0)), throwsArgumentError);
    expect(() => CoseKey.parse({1: 1, 3: -48, -1: List.filled(1312, 0)}),
        throwsArgumentError);
    expect(
        () => CoseKey.parse({
              1: 7,
              3: -48,
              -1: List.filled(1312, 0),
              -2: [1]
            }),
        throwsArgumentError);
    expect(
        () => CoseKey.parse({
              1: 2,
              3: -7,
              -1: 2,
              -2: List.filled(32, 0),
              -3: List.filled(32, 0)
            }),
        throwsArgumentError);
    final key = MLDSA44.fromPublicKey(List.filled(1312, 0));
    expect(() => key[3] = -49, throwsUnsupportedError);
    expect(() => (key[-1] as List)[0] = 1, throwsUnsupportedError);
    expect(() => key.verify([], [], context: [1]), throwsArgumentError);
    expect(() => key.verify([], [], mlDsaMode: 'hash'), throwsArgumentError);
    expect(
        () => CoseConfiguration(
            compatibilityAlgorithms: {-48: SignatureAlgorithm.mlDsa65}),
        throwsArgumentError);
    final compat = CoseConfiguration(
        compatibilityAlgorithms: {-65538: SignatureAlgorithm.mlDsa44});
    final alias = CoseKey.parse({1: 7, 3: -65538, -1: List.filled(1312, 0)},
        configuration: compat);
    expect(alias, isA<MLDSA44>());
    expect(alias.algorithmId, -65538);
    expect(CoseKey.parse(Map.from(alias)), isA<UnsupportedKey>());
  });
  test('truncated headers and sequential CBOR behavior', () {
    for (var length = 0; length < 37; length++) {
      expect(() => AuthenticatorData.parse(List.filled(length, 0)),
          throwsFormatException);
    }
    expect(() => cbor.decode([0xa0, 0xa0]), throwsFormatException);
    final ext = AuthenticatorData.parse(
        [...auth.sublist(0, 32), 0x81, 0, 0, 0, 0, 0xa0]);
    expect(ext.extensions, isEmpty);
    expect(
        () => AuthenticatorData.parse(
            [...auth.sublist(0, 32), 0x81, 0, 0, 0, 0, 0x80]),
        throwsFormatException);
  });
}
