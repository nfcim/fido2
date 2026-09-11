import 'dart:convert';
import 'package:cbor/cbor.dart';
import 'package:fido2/fido2.dart';
import 'package:test/test.dart';
import 'fixtures/fixtures.dart';
import 'support.dart';

final _fixture = (jsonDecode(fixtureJson) as Map)['packed'] as Map;
List<int> _decode(String value) => base64Url.decode(base64Url.normalize(value));
List<int> _bytes(String field) => _decode(_fixture[field] as String);
String _b64(List<int> bytes) => base64Url.encode(bytes).replaceAll('=', '');
List<int> _certificate(String name) =>
    _decode((_fixture['certificates'] as Map)[name] as String);

Map<String, dynamic> _statement({String certificate = 'valid'}) => {
  'alg': -7,
  'sig': CborBytes(_bytes('sig')),
  'x5c': [CborBytes(_certificate(certificate)), CborBytes(_bytes('root'))],
};
Map<String, dynamic> _registration({
  String format = 'packed',
  Map<String, dynamic>? statement,
  List<int>? authData,
  List<int>? clientData,
}) => {
  'id': _fixture['id'],
  'rawId': _fixture['id'],
  'type': 'public-key',
  'response': {
    'clientDataJSON': _b64(clientData ?? _bytes('clientDataJSON')),
    'attestationObject': _b64(
      cbor.encode(
        CborValue({
          'fmt': format,
          'attStmt': statement ?? _statement(),
          'authData': CborBytes(authData ?? _bytes('authData')),
        }),
      ),
    ),
  },
};
Fido2Server _server({
  AttestationVerifier? verifier,
  Set<String> formats = const {'none', 'packed'},
  List<int> algorithms = const [-7, -8],
}) => Fido2Server(
  Fido2Config(
    rpId: 'example.com',
    attestationVerifier: verifier,
    attestationFormats: formats,
    signatureAlgorithms: algorithms,
  ),
);
RegisteredCredential _complete(
  Map<String, dynamic> registration, {
  Fido2Server? server,
}) => (server ?? _server()).registerComplete(
  registration,
  expectedChallenge: _bytes('challenge'),
);

void main() {
  setUpAll(initializeCrypto);

  test('ES256 certificate attests an Ed25519 credential, both APIs agree', () {
    final registration = _registration();
    // Offered algorithms constrain the new credential, not the attestation key.
    final server = _server(algorithms: [-8]);
    final stored = _complete(registration, server: server);
    expect(stored.publicKey.algorithmId, -8);
    expect(stored.signCount, 190);
    expect(stored.id, _bytes('id'));
    final evidence = stored.attestation!;
    expect(evidence.format, 'packed');
    expect(evidence.type, AttestationType.basic);
    expect(evidence.aaguid, List.generate(16, (i) => i));
    expect(evidence.trustPath, [_certificate('valid'), _bytes('root')]);
    expect(() => evidence.trustPath.first[0] = 0, throwsUnsupportedError);
    expect(() => evidence.trustPath.clear(), throwsUnsupportedError);
    expect(() => evidence.aaguid[0] = 0, throwsUnsupportedError);
    expect(stored.toJson()['attestation'], evidence.toJson());
    final response = registration['response'] as Map;
    final legacy = server.completeRegistration(
      response['clientDataJSON'] as String,
      response['attestationObject'] as String,
      _fixture['challenge'] as String,
      offeredAlgorithms: [-8],
    );
    expect(legacy.attestation!.toJson(), evidence.toJson());
    expect(legacy.toJson()['attestation'], evidence.toJson());
    expect(legacy.credentialId, stored.id);
  });

  test('Ed25519 certificate attestation and self attestation', () {
    final statement = {'alg': -8, 'sig': CborBytes(_bytes('selfSig'))};
    final self = _complete(_registration(statement: statement)).attestation!;
    expect(self.type, AttestationType.self);
    expect(self.trustPath, isEmpty);
    final basic = _complete(
      _registration(
        statement: {
          ...statement,
          'x5c': [CborBytes(_certificate('ed25519'))],
        },
      ),
    ).attestation!;
    expect(basic.type, AttestationType.basic);
  });

  test('AAGUID extension is optional', () {
    expect(
      _complete(
        _registration(statement: _statement(certificate: 'noAaguid')),
      ).attestation!.type,
      AttestationType.basic,
    );
  });

  for (final name in [
    'wrongAaguid',
    'shortAaguid',
    'criticalAaguid',
    'ca',
    'noBasicConstraints',
    'wrongOu',
    'missingCountry',
    'missingOrganization',
    'missingCommonName',
  ]) {
    test('reject invalid packed leaf profile: $name', () {
      expect(
        () =>
            _complete(_registration(statement: _statement(certificate: name))),
        throwsFormatException,
      );
    });
  }

  test(
    'reject malformed DER, trailing DER and certificate algorithm mismatch',
    () {
      for (final cert in [
        <int>[1, 2],
        [..._certificate('valid'), 0],
      ]) {
        expect(
          () => _complete(
            _registration(
              statement: {
                ..._statement(),
                'x5c': [CborBytes(cert)],
              },
            ),
          ),
          throwsFormatException,
        );
      }
      expect(
        () => _complete(_registration(statement: {..._statement(), 'alg': -8})),
        throwsFormatException,
      );
    },
  );

  test(
    'reject tampered signatures, authData and original clientData bytes',
    () {
      final sig = _bytes('sig');
      sig[sig.length - 1] ^= 1;
      final auth = _bytes('authData');
      auth[36] ^= 1; // Change counter without invalidating structure.
      for (final registration in [
        _registration(statement: {..._statement(), 'sig': CborBytes(sig)}),
        _registration(authData: auth),
        // Semantically identical JSON still has a different signed hash.
        _registration(clientData: [..._bytes('clientDataJSON'), 32]),
      ]) {
        expect(() => _complete(registration), throwsA(isA<CryptoException>()));
      }
      final selfSig = _bytes('selfSig')..[0] ^= 1;
      expect(
        () => _complete(
          _registration(statement: {'alg': -8, 'sig': CborBytes(selfSig)}),
        ),
        throwsA(isA<CryptoException>()),
      );
    },
  );

  test('reject malformed packed statements and unsupported ECDAA', () {
    final statements = <Map<String, dynamic>>[
      {},
      {..._statement()}..remove('alg'),
      {..._statement()}..remove('sig'),
      {..._statement(), 'alg': '-7'},
      {..._statement(), 'alg': CborInt(BigInt.parse('18446744073709551615'))},
      {..._statement(), 'alg': -257},
      {..._statement(), 'sig': 'hex'},
      {..._statement(), 'sig': CborBytes([])},
      {..._statement(), 'x5c': null},
      {..._statement(), 'x5c': []},
      {
        ..._statement(),
        'x5c': [CborBytes([])],
      },
      {
        ..._statement(),
        'x5c': ['base64 certificate'],
      },
      {..._statement(), 'x5c': CborBytes(_certificate('valid'))},
      {
        ..._statement(),
        'ecdaaKeyId': CborBytes([1]),
      },
      {'alg': -7, 'sig': CborBytes(_bytes('selfSig'))},
    ];
    for (final statement in statements) {
      expect(
        () => _complete(_registration(statement: statement)),
        throwsFormatException,
        reason: statement.keys.toString(),
      );
    }
  });

  test('trust policy is optional and runs only after validation', () {
    var calls = 0;
    final server = _server(
      verifier: (evidence) {
        calls++;
        expect(evidence.type, AttestationType.basic);
        return false;
      },
    );
    final registration = _registration();
    expect(
      () => _complete(registration, server: server),
      throwsFormatException,
    );
    expect(calls, 1);
    final response = registration['response'] as Map;
    expect(
      () => server.completeRegistration(
        response['clientDataJSON'] as String,
        response['attestationObject'] as String,
        _fixture['challenge'] as String,
      ),
      throwsFormatException,
    );
    expect(calls, 2);
    final invalidId = _registration()..addAll({'id': 'BAUG', 'rawId': 'BAUG'});
    expect(() => _complete(invalidId, server: server), throwsFormatException);
    final auth = _bytes('authData')..[36] ^= 1;
    expect(
      () => _complete(_registration(authData: auth), server: server),
      throwsA(isA<CryptoException>()),
    );
    expect(calls, 2);
    expect(
      _complete(
        registration,
        server: _server(verifier: (_) => true),
      ).attestation,
      isNotNull,
    );
  });

  test(
    'policy also receives none/self, so they cannot bypass required trust',
    () {
      final seen = <AttestationType>[];
      final server = _server(
        verifier: (evidence) {
          seen.add(evidence.type);
          return false;
        },
      );
      expect(
        () => _complete(
          _registration(format: 'none', statement: {}),
          server: server,
        ),
        throwsFormatException,
      );
      expect(
        () => _complete(
          _registration(
            statement: {'alg': -8, 'sig': CborBytes(_bytes('selfSig'))},
          ),
          server: server,
        ),
        throwsFormatException,
      );
      expect(seen, [AttestationType.none, AttestationType.self]);
    },
  );

  test('format allowlist is independent of conveyance preference', () {
    final config = Fido2Config(
      rpId: 'example.com',
      attestation: AttestationConveyancePreference.direct,
    );
    expect(
      Fido2Server(config).generateRegistrationOptions('u', 'U')['attestation'],
      'direct',
    );
    expect(
      _server().generateRegistrationOptions('u', 'U')['attestation'],
      'none',
    );
    final none = _registration(format: 'none', statement: {});
    expect(_complete(none).attestation!.type, AttestationType.none);
    expect(
      () => _complete(_registration(), server: _server(formats: {'none'})),
      throwsFormatException,
    );
    expect(
      () => _complete(none, server: _server(formats: {'packed'})),
      throwsFormatException,
    );
    expect(
      () => _complete(_registration(format: 'tpm')),
      throwsFormatException,
    );
    expect(
      () => _complete(_registration(format: 'none')),
      throwsFormatException,
    );
    expect(
      () => Fido2Config(rpId: 'example.com', attestationFormats: {}),
      throwsArgumentError,
    );
    expect(
      () => Fido2Config(rpId: 'example.com', attestationFormats: {'tpm'}),
      throwsArgumentError,
    );
  });
}
