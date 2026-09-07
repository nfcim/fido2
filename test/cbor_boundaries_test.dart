import 'package:cbor/cbor.dart';
import 'package:fido2/fido2.dart';
import 'package:fido2/src/strict_cbor.dart';
import 'package:test/test.dart';

void main() {
  test('compound labels, integer range and nesting boundaries', () {
    for (final pair in [
      [
        [0x81, 1],
        [0x9f, 1, 0xff],
      ],
      [
        [0xa2, 1, 2, 3, 4],
        [0xa2, 3, 4, 1, 2],
      ],
    ]) {
      expect(
        () => decodeStrictCbor([0xa2, ...pair[0], 0, ...pair[1], 1]),
        throwsFormatException,
      );
    }
    final nestedKey = [...List.filled(63, 0x81), 0];
    expect(
      () => decodeStrictCbor([0xa2, ...nestedKey, 0, ...nestedKey, 1]),
      throwsFormatException,
    );
    for (final label in [1, 3, -1]) {
      final key = CborMap({
        CborSmallInt(1): CborSmallInt(2),
        CborSmallInt(3): CborSmallInt(-7),
        CborSmallInt(label): CborInt(BigInt.parse('18446744073709551615')),
      });
      expect(() => CoseKey.fromCborMap(key), throwsFormatException);
    }
    expect(
      () => CoseKey.fromCborMap(
        CborMap({
          CborInt(BigInt.parse('18446744073709551615')): CborSmallInt(0),
        }),
      ),
      throwsFormatException,
    );
    expect(decodeStrictCbor([...List.filled(64, 0x81), 0]), isA<CborList>());
    for (final leaf in [0, 0x80]) {
      expect(
        () => decodeStrictCbor([...List.filled(65, 0x81), leaf]),
        throwsFormatException,
      );
    }
    expect(
      () => decodeStrictCbor([...List.filled(64, 0x81), 0x80]),
      throwsFormatException,
    );
  });

  test('getInfo validates field and element types', () {
    final valid = <int, dynamic>{
      1: ['FIDO_2_1'],
      3: CborBytes(List.filled(16, 0)),
    };
    for (final entry in <int, dynamic>{
      1: [1],
      2: [1],
      3: List.filled(16, 0),
      4: {'rk': 1},
      5: '1024',
      6: ['2'],
      9: [1],
      10: [
        {'type': 1, 'alg': -7},
      ],
      12: 1,
      19: {'FIDO': '1'},
      21: ['1'],
    }.entries) {
      expect(
        () => AuthenticatorInfo.decode(
          cbor.encode(CborValue({...valid, entry.key: entry.value})),
        ),
        throwsFormatException,
      );
    }
    expect(
      () => AuthenticatorInfo.decode(
        cbor.encode(
          CborValue({
            ...valid,
            3: CborBytes([1]),
          }),
        ),
      ),
      throwsFormatException,
    );
  });

  test('malformed COSE wire fields report format errors', () {
    final wire = cbor.encode(CborValue({1: 2, 3: -7, -1: 1}));
    expect(() => CoseKey.fromCbor(wire), throwsFormatException);
    expect(
      () => CoseKey.fromCborMap(cbor.decode(wire) as CborMap),
      throwsFormatException,
    );
    expect(
      () => ClientPinResponse.decode(
        cbor.encode(
          CborValue({
            1: CborValue({1: 2, -1: 1}),
          }),
        ),
      ),
      throwsFormatException,
    );
  });

  test('algorithm enumeration separates signatures from key agreement', () {
    expect(CoseKey.supportedAlgorithms(), contains(-25));
    expect(CoseKey.supportedSignatureAlgorithms(), isNot(contains(-25)));
    expect(
      CoseKey.supportedSignatureAlgorithms(),
      containsAll([-7, -8, -9, -19, -48, -49, -50]),
    );
  });

  test('makeCredential and getAssertion require typed response fields', () {
    final make = <int, dynamic>{
      1: 'none',
      2: CborBytes([1]),
      3: <String, dynamic>{},
    };
    final get = <int, dynamic>{
      1: {
        'type': 'public-key',
        'id': CborBytes([42]),
      },
      2: CborBytes([1]),
      3: CborBytes([2]),
    };
    for (final label in [1, 2, 3]) {
      final missingMake = Map<int, dynamic>.from(make)..remove(label);
      final missingGet = Map<int, dynamic>.from(get)..remove(label);
      expect(
        () =>
            MakeCredentialResponse.decode(cbor.encode(CborValue(missingMake))),
        throwsFormatException,
      );
      expect(
        () => GetAssertionResponse.decode(cbor.encode(CborValue(missingGet))),
        throwsFormatException,
      );
      final invalidMake = {...make, label: 42};
      final invalidGet = {...get, label: 42};
      expect(
        () =>
            MakeCredentialResponse.decode(cbor.encode(CborValue(invalidMake))),
        throwsFormatException,
      );
      expect(
        () => GetAssertionResponse.decode(cbor.encode(CborValue(invalidGet))),
        throwsFormatException,
      );
    }
    final requested = PublicKeyCredentialDescriptor(
      type: 'public-key',
      id: [42],
    );
    final omitted = Map<int, dynamic>.from(get)..remove(1);
    final decoded = GetAssertionResponse.decode(
      cbor.encode(CborValue(omitted)),
      requestedCredential: requested,
    );
    expect(decoded.credential.id, [42]);
    expect(decoded.signature, [2]);
  });

  test(
    'credential metadata retains optional names, transports and COSE ID',
    () {
      final response = CredentialManagementResponse.decode(
        cbor.encode(
          CborValue({
            6: {
              'id': CborBytes([42]),
            },
            7: {
              'type': 'public-key',
              'id': CborBytes([1]),
              'transports': ['usb', 'nfc'],
            },
            0x80: -49,
          }),
        ),
      );
      expect(response.user!.name, isNull);
      expect(response.user!.displayName, isNull);
      expect(response.credentialId!.transports, ['usb', 'nfc']);
      expect(response.toJson()['coseAlgorithm'], -49);
    },
  );

  test('manual COSE arrays, empty arrays and explicit bytes retain types', () {
    for (final key in [
      UnsupportedKey({
        1: 99,
        3: -60000,
        4: [1, 2],
        42: <int>[],
        43: CborBytes([1, 2]),
      }),
      ES256({
        1: 2,
        3: -7,
        -1: 1,
        -2: List.filled(32, 1),
        -3: List.filled(32, 2),
        4: [1, 2],
        42: <int>[],
        43: CborBytes([1, 2]),
      }),
    ]) {
      final map = key.toCborMap();
      expect(map[CborSmallInt(4)], isA<CborList>());
      expect(map[CborSmallInt(42)], isA<CborList>());
      expect(map[CborSmallInt(43)], isA<CborBytes>());
      final wire = cbor.encode(map);
      expect(cbor.encode(CoseKey.fromCbor(wire).toCborMap()), wire);
    }
  });

  test('reject duplicate labels before map construction', () {
    for (final wire in [
      [0xa2, 1, 1, 1, 2],
      [0xa2, 1, 1, 0x18, 1, 2], // Same integer, different width.
      [0xbf, 1, 1, 1, 2, 0xff],
      [0xa1, 1, 0xa2, 2, 1, 2, 2], // Nested map.
      [0xa2, 0x61, 0x61, 1, 0x7f, 0x61, 0x61, 0xff, 2],
    ]) {
      expect(() => decodeStrictCbor(wire), throwsFormatException);
      expect(() => CoseKey.fromCbor(wire), throwsFormatException);
      expect(() => ClientPinResponse.decode(wire), throwsFormatException);
      expect(
        () => CredentialManagementResponse.decode(wire),
        throwsFormatException,
      );
    }
    expect(
      () => AuthenticatorData.parse([
        ...List.filled(32, 0),
        0x41,
        0,
        0,
        0,
        0,
        ...List.filled(16, 0),
        0,
        1,
        1,
        0xa2,
        1,
        1,
        1,
        2,
      ]),
      throwsFormatException,
    );
    expect(
      () => AuthenticatorData.parse([
        ...List.filled(32, 0),
        0x81,
        0,
        0,
        0,
        0,
        0xa2,
        0x61,
        0x61,
        1,
        0x61,
        0x61,
        2,
      ]),
      throwsFormatException,
    );
  });

  test('CBOR scanner handles containers, truncation and bounded nesting', () {
    for (final wire in [
      [0xbf, 1, 0x9f, 1, 2, 0xff, 0xff],
      [0xa1, 1, 0x5f, 0x42, 1, 2, 0xff],
      [0xa1, 1, 0xfb, 0x3f, 0xf0, 0, 0, 0, 0, 0, 0],
      [0xa1, 1, 0xd8, 100, 0x80],
    ]) {
      expect(decodeStrictCbor(wire), cbor.decode(wire));
      for (var end = 0; end < wire.length; end++) {
        expect(
          () => decodeStrictCbor(wire.sublist(0, end)),
          throwsFormatException,
        );
      }
    }
    for (final wire in [
      [0xa0, 0xa0],
      [0xff],
      [0xa1, 1],
      [0x5b, ...List.filled(8, 255)],
      [...List.filled(66, 0x81), 0],
    ]) {
      expect(() => decodeStrictCbor(wire), throwsFormatException);
    }
  });

  test('CTAP wrong root and nested field types produce FormatException', () {
    for (final value in [1, [], 'map', null]) {
      final wire = cbor.encode(CborValue(value));
      expect(() => ClientPinResponse.decode(wire), throwsFormatException);
      expect(
        () => CredentialManagementResponse.decode(wire),
        throwsFormatException,
      );
    }
    for (final map in [
      {1: 1},
      {
        2: [1, 2],
      },
      {3: 'x'},
      {4: 1},
      {5: false},
    ]) {
      expect(
        () => ClientPinResponse.decode(cbor.encode(CborValue(map))),
        throwsFormatException,
      );
    }
    for (final map in [
      {1: 'x'},
      {3: 1},
      {
        3: {'id': 1},
      },
      {
        4: [1],
      },
      {
        6: {
          'id': [1],
          'name': 'u',
          'displayName': 'U',
        },
      },
      {
        6: {
          'id': CborBytes([1]),
          'name': 1,
          'displayName': 'U',
        },
      },
      {
        7: {'type': 'public-key'},
      },
      {8: []},
      {9: false},
      {
        11: [1],
      },
    ]) {
      expect(
        () => CredentialManagementResponse.decode(cbor.encode(CborValue(map))),
        throwsFormatException,
      );
    }
  });
}
