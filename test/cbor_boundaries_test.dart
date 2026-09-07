import 'package:cbor/cbor.dart';
import 'package:fido2/fido2.dart';
import 'package:fido2/src/strict_cbor.dart';
import 'package:test/test.dart';

void main() {
  test('manual COSE arrays, empty arrays and explicit bytes retain types', () {
    for (final key in [
      UnsupportedKey({
        1: 99,
        3: -60000,
        4: [1, 2],
        42: <int>[],
        43: CborBytes([1, 2])
      }),
      ES256({
        1: 2,
        3: -7,
        -1: 1,
        -2: List.filled(32, 1),
        -3: List.filled(32, 2),
        4: [1, 2],
        42: <int>[],
        43: CborBytes([1, 2])
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
      expect(() => Ctap2.parseClientPinResponse(wire), throwsFormatException);
      expect(() => Ctap2.parseCredentialManagementResponse(wire),
          throwsFormatException);
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
        throwsFormatException);
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
        throwsFormatException);
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
        expect(() => decodeStrictCbor(wire.sublist(0, end)),
            throwsFormatException);
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
      expect(() => Ctap2.parseClientPinResponse(wire), throwsFormatException);
      expect(() => Ctap2.parseCredentialManagementResponse(wire),
          throwsFormatException);
    }
    for (final map in [
      {1: 1},
      {
        2: [1, 2]
      },
      {3: 'x'},
      {4: 1},
      {5: false}
    ]) {
      expect(() => Ctap2.parseClientPinResponse(cbor.encode(CborValue(map))),
          throwsFormatException);
    }
    for (final map in [
      {1: 'x'},
      {3: 1},
      {
        3: {'id': 1}
      },
      {
        4: [1]
      },
      {
        6: {
          'id': [1],
          'name': 'u',
          'displayName': 'U'
        }
      },
      {
        6: {
          'id': CborBytes([1]),
          'name': 1,
          'displayName': 'U'
        }
      },
      {
        7: {'type': 'public-key'}
      },
      {8: []},
      {9: false},
      {
        11: [1]
      },
    ]) {
      expect(
          () => Ctap2.parseCredentialManagementResponse(
              cbor.encode(CborValue(map))),
          throwsFormatException);
    }
  });
}
