import 'dart:convert';
import 'dart:typed_data';

import 'package:cbor/cbor.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart';
import 'package:fido2/src/cose.dart';
import 'package:fido2/src/server/base.dart';
import 'package:fido2/src/server/entities/authenticator_data.dart';
import 'package:fido2/src/server/config.dart';
import 'package:fido2/src/server/entities/registration_data.dart';
import 'package:fido2/src/server/entities/verification_data.dart';
import 'package:test/test.dart';

void main() {
  final config = Fido2Config(
    rpId: 'webauthn.io',
    rpName: 'Webauthn.io Test',
  );

  final server = Fido2Server(config);
  group('Fido2Server registration', () {
    test('completeRegistration with constructed attestation (Ed25519, none)',
        () async {
      // 1) RP generates registration options and stores expectedChallenge
      final options =
          server.generateRegistrationOptions('testuser', 'Test User');
      final String challenge = options['challenge'];

      // 2) Construct clientDataJSON
      final clientData = {
        'type': 'webauthn.create',
        'challenge': challenge,
        'origin': 'https://webauthn.io',
        'crossOrigin': false,
      };
      final clientDataBase64 =
          base64Url.encode(utf8.encode(json.encode(clientData)));

      // 3) Build authenticatorData with attested credential data
      final rpIdHash = crypto.sha256.convert(utf8.encode(config.rpId)).bytes;
      final flags = 0x41; // User Present + Attested Credential Data
      final signCount = 1;
      final aaguid = Uint8List(16); // zeros
      final credentialId = Uint8List.fromList([1, 2, 3, 4]);

      // Generate an Ed25519 key and COSE public key
      final algorithm = Ed25519();
      final keyPair = await algorithm.newKeyPair();
      final publicKey = await keyPair.extractPublicKey();
      final cosePubKey = EdDSA.fromPublicKey(publicKey.bytes).toCborMap();

      final authDataBuilder = BytesBuilder()
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
        ..add(cbor.encode(cosePubKey));
      final authDataBytes = authDataBuilder.toBytes();

      // 4) Wrap into attestationObject (fmt: none)
      final attObj = CborMap({
        CborString('fmt'): CborString('none'),
        CborString('authData'): CborBytes(authDataBytes),
        CborString('attStmt'): CborMap({}),
      });
      final attestationObjectBase64 =
          base64Url.encode(cbor.encode(CborValue(attObj)));

      // 5) Complete registration
      final result = server.completeRegistration(
        clientDataBase64,
        attestationObjectBase64,
        challenge,
      );

      expect(result, isA<RegistrationResult>());
      expect(result.credentialId, isNotEmpty);
      expect(result.credentialPublicKey, isA<CborMap>());
      // Basic checks on the COSE key
      final pubKey = result.credentialPublicKey;
      expect(pubKey[CborInt(BigInt.from(CoseKey.ktyIdx))]!.toObject(),
          equals(CoseKey.ktyOKP));
      expect(pubKey[CborInt(BigInt.from(CoseKey.algIdx))]!.toObject(),
          equals(EdDSA.algorithm));
      expect(pubKey[CborInt(BigInt.from(CoseKey.okpCrvIdx))]!.toObject(),
          equals(CoseKey.okpCrvEd25519));
    });

    test('completeRegistration fails on mismatched challenge', () async {
      // 1) Generate options and use the provided challenge inside clientData
      final options = server.generateRegistrationOptions('user2', 'User 2');
      final String goodChallenge = options['challenge'];

      // 2) clientDataJSON uses the correct challenge, but we will pass a different expectedChallenge
      final clientData = {
        'type': 'webauthn.create',
        'challenge': goodChallenge,
        'origin': 'https://webauthn.io',
        'crossOrigin': false,
      };
      final clientDataBase64 =
          base64Url.encode(utf8.encode(json.encode(clientData)));

      // 3) Construct minimal valid authenticatorData with correct rpIdHash
      final rpIdHash = crypto.sha256.convert(utf8.encode(config.rpId)).bytes;
      final flags = 0x41; // User Present + Attested Credential Data
      final signCount = 1;
      final aaguid = Uint8List(16);
      final credentialId = Uint8List.fromList([5, 6, 7, 8]);

      final algorithm = Ed25519();
      final keyPair = await algorithm.newKeyPair();
      final publicKey = await keyPair.extractPublicKey();
      final cosePubKey = EdDSA.fromPublicKey(publicKey.bytes).toCborMap();

      final authDataBuilder = BytesBuilder()
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
        ..add(cbor.encode(cosePubKey));
      final authDataBytes = authDataBuilder.toBytes();

      final attObj = CborMap({
        CborString('fmt'): CborString('none'),
        CborString('authData'): CborBytes(authDataBytes),
        CborString('attStmt'): CborMap({}),
      });
      final attestationObjectBase64 =
          base64Url.encode(cbor.encode(CborValue(attObj)));

      // 4) Pass a wrong expectedChallenge to trigger mismatch
      const wrongExpectedChallenge = 'not-the-same-challenge';

      expect(
        () => server.completeRegistration(
          clientDataBase64,
          attestationObjectBase64,
          wrongExpectedChallenge,
        ),
        throwsA(predicate((e) =>
            e is Exception && e.toString().contains('challenge mismatch'))),
      );
    });

    test('completeRegistration fails on mismatched rpId', () async {
      // 1) Generate options and use the provided challenge
      final options = server.generateRegistrationOptions('user3', 'User 3');
      final String challenge = options['challenge'];

      // 2) clientDataJSON with correct origin for config.rpId
      final clientData = {
        'type': 'webauthn.create',
        'challenge': challenge,
        'origin': 'https://webauthn.io',
        'crossOrigin': false,
      };
      final clientDataBase64 =
          base64Url.encode(utf8.encode(json.encode(clientData)));

      // 3) Build authenticatorData with WRONG rpIdHash (use a different domain)
      final wrongRpIdHash =
          crypto.sha256.convert(utf8.encode('evil.com')).bytes;
      final flags = 0x41; // User Present + Attested Credential Data
      final signCount = 1;
      final aaguid = Uint8List(16);
      final credentialId = Uint8List.fromList([9, 10, 11, 12]);

      final algorithm = Ed25519();
      final keyPair = await algorithm.newKeyPair();
      final publicKey = await keyPair.extractPublicKey();
      final cosePubKey = EdDSA.fromPublicKey(publicKey.bytes).toCborMap();

      final authDataBuilder = BytesBuilder()
        ..add(wrongRpIdHash)
        ..addByte(flags)
        ..add((ByteData(4)..setUint32(0, signCount, Endian.big))
            .buffer
            .asUint8List())
        ..add(aaguid)
        ..add((ByteData(2)..setUint16(0, credentialId.length, Endian.big))
            .buffer
            .asUint8List())
        ..add(credentialId)
        ..add(cbor.encode(cosePubKey));
      final authDataBytes = authDataBuilder.toBytes();

      final attObj = CborMap({
        CborString('fmt'): CborString('none'),
        CborString('authData'): CborBytes(authDataBytes),
        CborString('attStmt'): CborMap({}),
      });
      final attestationObjectBase64 =
          base64Url.encode(cbor.encode(CborValue(attObj)));

      expect(
        () => server.completeRegistration(
          clientDataBase64,
          attestationObjectBase64,
          challenge,
        ),
        throwsA(predicate((e) =>
            e is Exception && e.toString().contains('rpIdHash mismatch'))),
      );
    });
  });

  group('Fido2Server verification', () {
    final config = Fido2Config(
      rpId: 'webauthn.io',
      rpName: 'Webauthn.io Test',
    );
    final server = Fido2Server(config);

    Uint8List beUint32(int v) {
      final b = ByteData(4);
      b.setUint32(0, v, Endian.big);
      return b.buffer.asUint8List();
    }

    test('generateVerificationOptions returns challenge & rpId', () {
      final options = server.generateVerificationOptions();
      expect(options['challenge'], isA<String>());
      expect((options['challenge'] as String).isNotEmpty, isTrue);
      expect(options['rpId'], equals('webauthn.io'));
      expect(options['timeout'], equals(60000));
    });

    test('completeVerification succeeds for Ed25519 key', () async {
      // 1) RP generates verification options (challenge) and stores expectedChallenge
      final options = server.generateVerificationOptions();
      final String challenge = options['challenge'];

      // 2) Prepare a synthetic Ed25519 credential/public key (as stored by RP at registration)
      final algorithm = Ed25519();
      final keyPair = await algorithm.newKeyPair();
      final publicKey = await keyPair.extractPublicKey();
      final pubKeyBytes = publicKey.bytes;

      // Build COSE OKP (Ed25519) public key map using cose.dart helpers
      final cborPubKey = EdDSA.fromPublicKey(pubKeyBytes).toCborMap();

      // 3) Client creates clientDataJSON
      final clientData = {
        'type': 'webauthn.get',
        'challenge': challenge,
        'origin': 'https://webauthn.io',
        'crossOrigin': false,
      };
      final clientDataJson = json.encode(clientData);
      final clientDataBase64 = base64Url.encode(utf8.encode(clientDataJson));

      // 4) AuthenticatorData: rpIdHash || flags || signCount
      final rpIdHash = crypto.sha256.convert(utf8.encode(config.rpId)).bytes;
      final flags = [0x01]; // User present
      final signCount = beUint32(1);
      final authData =
          Uint8List.fromList([...rpIdHash, ...flags, ...signCount]);
      final authDataBase64 = base64Url.encode(authData);

      // 5) Sign (authData || SHA256(clientDataJSON)) with Ed25519
      final clientDataHash =
          crypto.sha256.convert(utf8.encode(clientDataJson)).bytes;
      final toSign = Uint8List.fromList([...authData, ...clientDataHash]);
      final sig = await algorithm.sign(toSign, keyPair: keyPair);
      final signatureBase64 = base64Url.encode(sig.bytes);

      // 6) Verify on server
      final result = await server.completeVerification(
        clientDataBase64,
        authDataBase64,
        signatureBase64,
        challenge,
        cborPubKey,
        0, // Stored sign count
      );

      expect(result, isA<VerificationResult>());
      expect(result.userPresent, isTrue);
      expect(result.userVerified, isFalse);
      expect(result.signCount, equals(1));
    });

    test('completeVerification fails on mismatched challenge', () async {
      final options = server.generateVerificationOptions();
      final String challenge = options['challenge'];

      final algorithm = Ed25519();
      final keyPair = await algorithm.newKeyPair();
      final publicKey = await keyPair.extractPublicKey();
      final pubKeyBytes = publicKey.bytes;
      final cborPubKey = EdDSA.fromPublicKey(pubKeyBytes).toCborMap();

      final clientData = {
        'type': 'webauthn.get',
        'challenge': challenge,
        'origin': 'https://webauthn.io',
        'crossOrigin': false,
      };
      final clientDataJson = json.encode(clientData);
      final clientDataBase64 = base64Url.encode(utf8.encode(clientDataJson));

      final rpIdHash = crypto.sha256.convert(utf8.encode(config.rpId)).bytes;
      final authData = Uint8List.fromList([...rpIdHash, 0x01, 0, 0, 0, 1]);
      final authDataBase64 = base64Url.encode(authData);

      final clientDataHash =
          crypto.sha256.convert(utf8.encode(clientDataJson)).bytes;
      final toSign = Uint8List.fromList([...authData, ...clientDataHash]);
      final sig = await algorithm.sign(toSign, keyPair: keyPair);
      final signatureBase64 = base64Url.encode(sig.bytes);

      expect(
        () => server.completeVerification(
          clientDataBase64,
          authDataBase64,
          signatureBase64,
          'wrong-challenge',
          cborPubKey,
          0,
        ),
        throwsA(predicate((e) =>
            e is Exception && e.toString().contains('challenge mismatch'))),
      );
    });

    test('completeVerification fails on mismatched signature', () async {
      final options = server.generateVerificationOptions();
      final String challenge = options['challenge'];

      final algorithm = Ed25519();
      final keyPair = await algorithm.newKeyPair();
      final publicKey = await keyPair.extractPublicKey();
      final pubKeyBytes = publicKey.bytes;
      final cborPubKey = EdDSA.fromPublicKey(pubKeyBytes).toCborMap();

      final clientData = {
        'type': 'webauthn.get',
        'challenge': challenge,
        'origin': 'https://webauthn.io',
        'crossOrigin': false,
      };
      final clientDataJson = json.encode(clientData);
      final clientDataBase64 = base64Url.encode(utf8.encode(clientDataJson));

      final rpIdHash = crypto.sha256.convert(utf8.encode(config.rpId)).bytes;
      final authData = Uint8List.fromList([...rpIdHash, 0x01, 0, 0, 0, 1]);
      final authDataBase64 = base64Url.encode(authData);

      // Make a signature with a different key (invalid w.r.t public key)
      final wrongKeyPair = await algorithm.newKeyPair();
      final clientDataHash =
          crypto.sha256.convert(utf8.encode(clientDataJson)).bytes;
      final toSign = Uint8List.fromList([...authData, ...clientDataHash]);
      final sig = await algorithm.sign(toSign, keyPair: wrongKeyPair);
      final signatureBase64 = base64Url.encode(sig.bytes);

      expect(
        () => server.completeVerification(
          clientDataBase64,
          authDataBase64,
          signatureBase64,
          challenge,
          cborPubKey,
          0,
        ),
        throwsA(predicate((e) =>
            e is Exception && e.toString().contains('signature verification'))),
      );
    });

    test('completeVerification fails on invalid sign count', () async {
      final options = server.generateVerificationOptions();
      final String challenge = options['challenge'];

      final algorithm = Ed25519();
      final keyPair = await algorithm.newKeyPair();
      final publicKey = await keyPair.extractPublicKey();
      final pubKeyBytes = publicKey.bytes;
      final cborPubKey = EdDSA.fromPublicKey(pubKeyBytes).toCborMap();

      final clientData = {
        'type': 'webauthn.get',
        'challenge': challenge,
        'origin': 'https://webauthn.io',
        'crossOrigin': false,
      };
      final clientDataJson = json.encode(clientData);
      final clientDataBase64 = base64Url.encode(utf8.encode(clientDataJson));

      // Authenticator returns sign count of 5
      final rpIdHash = crypto.sha256.convert(utf8.encode(config.rpId)).bytes;
      final authData = Uint8List.fromList([...rpIdHash, 0x01, 0, 0, 0, 5]);
      final authDataBase64 = base64Url.encode(authData);

      final clientDataHash =
          crypto.sha256.convert(utf8.encode(clientDataJson)).bytes;
      final toSign = Uint8List.fromList([...authData, ...clientDataHash]);
      final sig = await algorithm.sign(toSign, keyPair: keyPair);
      final signatureBase64 = base64Url.encode(sig.bytes);

      // RP has stored a sign count of 10 (higher than authenticator)
      expect(
        () => server.completeVerification(
          clientDataBase64,
          authDataBase64,
          signatureBase64,
          challenge,
          cborPubKey,
          10,
        ),
        throwsA(predicate((e) =>
            e is Exception &&
            e.toString().contains('sign count did not increase'))),
      );
    });
  });
  group('Real data from webauthn.io (EdDSA)', () {
    test('Registration succeeds', () {
      const clientDataBase64 =
          'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiOUkteUk2V2tPNzdia01XTjdJdTA5SUh3Yi0zcEFzc2VTMi0xelJCaVpWaExwYkEwaWZteENBQnRueEhYdE5fMjNWd3ZJcDVoMUhNUjQwM2FWa0Zsc1EiLCJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLmlvIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ';
      const attestationObjectBase64 =
          'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVindKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBFAAAAVAAAAAAAAAAAAAAAAAAAAAAARoqPJC6K5JBvdHdP1y4cW9JK1O0N0t4UKm1nwUV6oi4RAQF0puqSE8mcL3SyJJKzIM9AJiqUwalQoDl_KSULYIQe8P____ikAQEDJyAGIVggCp5bqsla5eaTxRTHpQmkDi7-XwEYW5WWKRiMnSU776s';
      const challenge =
          '9I-yI6WkO77bkMWN7Iu09IHwb-3pAsseS2-1zRBiZVhLpbA0ifmxCABtnxHXtN_23VwvIp5h1HMR403aVkFlsQ';

      final result = server.completeRegistration(
        clientDataBase64,
        attestationObjectBase64,
        challenge,
      );

      expect(result, isA<RegistrationResult>());
      expect(result.credentialId, isNotEmpty);
      expect(result.credentialPublicKey, isA<CborMap>());

      final pubKey = result.credentialPublicKey;
      final x = (pubKey[CborInt(BigInt.from(-2))] as CborBytes).bytes;
      expect(base64Url.encode(x),
          equals('Cp5bqsla5eaTxRTHpQmkDi7-XwEYW5WWKRiMnSU776s='));
    });
    test('Verification succeeds', () async {
      const clientDataBase64 =
          'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoidVgzbTdTOGVUN2xlSjhrTlZjenp1UFUwWXpGS2htSVlpcHotVEtHVUZVWFdnRkFiVDZvZUoxeUlUT2RENFo4ZHlRZ2x3TkR5eDVZOEF3QzZJMlp4MkEiLCJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLmlvIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ';
      const authDataBase64 =
          'dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvAFAAAAVg';
      const signatureBase64 =
          'qRCip8vGsCKRTh13c9xfdRgV_o75yFXKR3-hIsFm--WlmzSCLqZvmsUd_qyRkJXZQo-3nIWMiVb-HJQm7xmPBA';
      const challenge =
          'uX3m7S8eT7leJ8kNVczzuPU0YzFKhmIYipz-TKGUFUXWgFAbT6oeJ1yITOdD4Z8dyQglwNDyx5Y8AwC6I2Zx2A';

      final cborPubKey = EdDSA.fromPublicKey(
        base64Url.decode('Cp5bqsla5eaTxRTHpQmkDi7-XwEYW5WWKRiMnSU776s='),
      ).toCborMap();

      final result = await server.completeVerification(
        clientDataBase64,
        authDataBase64,
        signatureBase64,
        challenge,
        cborPubKey,
        0, // Stored sign count
      );

      expect(result, isA<VerificationResult>());
      expect(result.userPresent, isTrue);
      expect(result.userVerified, isTrue);
      expect(result.signCount, equals(86));
    });
  });

  group('Real data from webauthn.io (ES256)', () {
    test('Registration succeeds', () {
      const clientDataBase64 =
          'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoib3dxdWFzS2c5R3RHSWxBNmE3ekNnTEFrUTlWcFVMbFlUNWpPR1BZY3NpajRuaFc2TkxsWDRCUl9KQkJab1FsZ0tmYU1MM1JrZjVTQ3NEa2pTZFpkOVEiLCJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLmlvIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ';
      const attestationObjectBase64 =
          'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjKdKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBFAAAAYwAAAAAAAAAAAAAAAAAAAAAARkNIZuq_9TlVtKeOTuC_oU_8mM8IGfJVZS58mF_pnrvEAQF0puqSE8mcL3SyJJKzIM9AJiqUwalQoDl_KSULYIQe8P____mlAQIDJiABIVggPO8x8YWk2S-8Yr-M7oVTQI-175w9yqaiTOpxxNbuk4ciWCBrzO_bU03_ympwejDxc1fYZE1CgqCqiNCDpqKCr2bnFA';
      const challenge =
          'owquasKg9GtGIlA6a7zCgLAkQ9VpULlYT5jOGPYcsij4nhW6NLlX4BR_JBBZoQlgKfaML3Rkf5SCsDkjSdZd9Q';

      final result = server.completeRegistration(
        clientDataBase64,
        attestationObjectBase64,
        challenge,
      );

      expect(result, isA<RegistrationResult>());
      expect(result.credentialId, isNotEmpty);
      expect(result.credentialPublicKey, isA<CborMap>());

      final pubKey = result.credentialPublicKey;
      expect(pubKey[CborInt(BigInt.from(CoseKey.ktyIdx))]!.toObject(),
          equals(CoseKey.ktyEC2));
      expect(pubKey[CborInt(BigInt.from(CoseKey.algIdx))]!.toObject(),
          equals(ES256.algorithm));
      expect(pubKey[CborInt(BigInt.from(CoseKey.ec2CrvIdx))]!.toObject(),
          equals(CoseKey.ec2CrvP256));
      final x =
          (pubKey[CborInt(BigInt.from(CoseKey.ec2XIdx))] as CborBytes).bytes;
      final y =
          (pubKey[CborInt(BigInt.from(CoseKey.ec2YIdx))] as CborBytes).bytes;
      expect(x.length, equals(32));
      expect(y.length, equals(32));
    });

    test('Verification succeeds', () async {
      // Use the same attestation to recover the COSE public key
      const attestationObjectBase64 =
          'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjKdKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBFAAAAYwAAAAAAAAAAAAAAAAAAAAAARkNIZuq_9TlVtKeOTuC_oU_8mM8IGfJVZS58mF_pnrvEAQF0puqSE8mcL3SyJJKzIM9AJiqUwalQoDl_KSULYIQe8P____mlAQIDJiABIVggPO8x8YWk2S-8Yr-M7oVTQI-175w9yqaiTOpxxNbuk4ciWCBrzO_bU03_ympwejDxc1fYZE1CgqCqiNCDpqKCr2bnFA';

      String pad(String s) => s.padRight((s.length + 3) & ~3, '=');
      final attestationObject = cbor
          .decode(base64Url.decode(pad(attestationObjectBase64))) as CborMap;
      final authDataBytes =
          (attestationObject[CborString('authData')] as CborBytes).bytes;
      final authData =
          AuthenticatorData.parse(Uint8List.fromList(authDataBytes));
      final cborPubKey = authData.attestedCredentialData!.credentialPublicKey;

      // Provided assertion data
      const clientDataBase64 =
          'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiOS1UYnFXWW94MUdkUjVoRHJ6bmhpVzlKNlBoNGJsS0F4RkxTLV94ZjhlbGsyY242bWZuQjh4M283TjFpaVlkcTZUcEF4SVVMYnRJNWZXNHN6Z0p4WXciLCJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLmlvIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ';
      const authDataBase64 =
          'dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvAFAAAAZQ';
      const signatureBase64 =
          'MEUCIQDKsMny-fr-hwt-4QCBHCi-bWiB3xeA7ZaFGkgma-0Z7AIgIv5o4w3ImBF3ObQcXhPSuMJYKO5NixR1oN9lgq4K8B4';
      const challenge =
          '9-TbqWYox1GdR5hDrznhiW9J6Ph4blKAxFLS-_xf8elk2cn6mfnB8x3o7N1iiYdq6TpAxIULbtI5fW4szgJxYw';

      final result = await server.completeVerification(
        clientDataBase64,
        authDataBase64,
        signatureBase64,
        challenge,
        cborPubKey,
        0, // Stored sign count
      );

      expect(result, isA<VerificationResult>());
      expect(result.userPresent, isTrue);
      expect(result.userVerified, isTrue);
      expect(result.signCount, equals(101));
    });
  });
}
