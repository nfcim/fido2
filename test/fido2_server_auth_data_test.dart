import 'dart:typed_data';

import 'package:cbor/cbor.dart';
import 'package:fido2/src/server/entities/authenticator_data.dart';
import 'package:test/test.dart';

void main() {
  group('AuthenticatorData.parse', () {
    test('No attested data, no extensions', () {
      final rpIdHash = Uint8List(32)..fillRange(0, 32, 1);
      final flags = 0x01; // User Present
      final signCount = 123;

      final builder = BytesBuilder()
        ..add(rpIdHash)
        ..addByte(flags)
        ..add((ByteData(4)..setUint32(0, signCount, Endian.big))
            .buffer
            .asUint8List());
      final authDataBytes = builder.toBytes();

      final authData = AuthenticatorData.parse(authDataBytes);

      expect(authData.rpIdHash, equals(rpIdHash));
      expect(authData.flags, equals(flags));
      expect(authData.signCount, equals(signCount));
      expect(authData.userPresent, isTrue);
      expect(authData.userVerified, isFalse);
      expect(authData.hasAttestedCredentialData, isFalse);
      expect(authData.hasExtensions, isFalse);
      expect(authData.attestedCredentialData, isNull);
      expect(authData.extensions, isNull);
    });

    test('With attested credential data', () {
      final rpIdHash = Uint8List(32)..fillRange(0, 32, 2);
      final flags = 0x41; // User Present + Attested Data
      final signCount = 123;
      final aaguid = Uint8List(16)..fillRange(0, 16, 3);
      final credentialId = Uint8List.fromList([1, 2, 3, 4]);
      final credentialPublicKey = CborMap({
        CborSmallInt(1): CborSmallInt(2),
        CborSmallInt(3): CborBytes(Uint8List.fromList([4, 5, 6])),
      });

      final builder = BytesBuilder()
        ..add(rpIdHash)
        ..addByte(flags)
        ..add((ByteData(4)..setUint32(0, signCount, Endian.big))
            .buffer
            .asUint8List())
        ..add(aaguid)
        ..add((ByteData(2)..setUint16(0, credentialId.length, Endian.big))
            .buffer
            .asUint8List())
        ..add(credentialId)
        ..add(cbor.encode(credentialPublicKey));
      final authDataBytes = builder.toBytes();

      final authData = AuthenticatorData.parse(authDataBytes);

      expect(authData.hasAttestedCredentialData, isTrue);
      expect(authData.attestedCredentialData, isNotNull);
      expect(authData.attestedCredentialData!.aaguid, equals(aaguid));
      expect(
          authData.attestedCredentialData!.credentialId, equals(credentialId));
      expect(authData.attestedCredentialData!.credentialPublicKey.toString(),
          equals(credentialPublicKey.toString()));
      expect(authData.hasExtensions, isFalse);
      expect(authData.extensions, isNull);
    });

    test('With extensions but no attested data', () {
      final rpIdHash = Uint8List(32)..fillRange(0, 32, 4);
      final flags = 0x81; // User Present + Extensions
      final signCount = 123;
      final extensions = CborMap({
        CborString('hmac-secret'): CborBool(true),
      });

      final builder = BytesBuilder()
        ..add(rpIdHash)
        ..addByte(flags)
        ..add((ByteData(4)..setUint32(0, signCount, Endian.big))
            .buffer
            .asUint8List())
        ..add(cbor.encode(extensions));
      final authDataBytes = builder.toBytes();

      final authData = AuthenticatorData.parse(authDataBytes);

      expect(authData.hasAttestedCredentialData, isFalse);
      expect(authData.attestedCredentialData, isNull);
      expect(authData.hasExtensions, isTrue);
      expect(authData.extensions, isNotNull);
      expect(authData.extensions.toString(), equals(extensions.toString()));
    });

    test('With both attested data and extensions', () {
      final rpIdHash = Uint8List(32)..fillRange(0, 32, 5);
      final flags = 0xC1; // User Present + Attested Data + Extensions
      final signCount = 123;
      final aaguid = Uint8List(16)..fillRange(0, 16, 6);
      final credentialId = Uint8List.fromList([5, 6, 7, 8]);
      final credentialPublicKey = CborMap({CborSmallInt(1): CborSmallInt(2)});
      final extensions =
          CborMap({CborString('extKey'): CborString('extValue')});

      final cborPayload = CborList([credentialPublicKey, extensions]);

      final builder = BytesBuilder()
        ..add(rpIdHash)
        ..addByte(flags)
        ..add((ByteData(4)..setUint32(0, signCount, Endian.big))
            .buffer
            .asUint8List())
        ..add(aaguid)
        ..add((ByteData(2)..setUint16(0, credentialId.length, Endian.big))
            .buffer
            .asUint8List())
        ..add(credentialId)
        ..add(cbor.encode(cborPayload));
      final authDataBytes = builder.toBytes();

      final authData = AuthenticatorData.parse(authDataBytes);

      expect(authData.hasAttestedCredentialData, isTrue);
      expect(authData.attestedCredentialData, isNotNull);
      expect(authData.attestedCredentialData!.aaguid, equals(aaguid));
      expect(
          authData.attestedCredentialData!.credentialId, equals(credentialId));
      expect(authData.attestedCredentialData!.credentialPublicKey.toString(),
          equals(credentialPublicKey.toString()));

      expect(authData.hasExtensions, isTrue);
      expect(authData.extensions, isNotNull);
      expect(authData.extensions.toString(), equals(extensions.toString()));
    });

    test('Too short data', () {
      final rpIdHash = Uint8List(31); // Too short
      expect(
        () => AuthenticatorData.parse(rpIdHash),
        throwsA(isA<FormatException>()),
      );
    });

    test('Attested data is flagged but missing', () {
      final rpIdHash = Uint8List(32)..fillRange(0, 32, 1);
      final flags = 0x41; // Attested data flag is set
      final signCount = 123;

      final builder = BytesBuilder()
        ..add(rpIdHash)
        ..addByte(flags)
        ..add((ByteData(4)..setUint32(0, signCount, Endian.big))
            .buffer
            .asUint8List());
      final authDataBytes =
          builder.toBytes(); // No actual attested data appended

      expect(
        () => AuthenticatorData.parse(authDataBytes),
        throwsA(isA<FormatException>()),
      );
    });
  });
}
