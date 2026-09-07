import 'dart:convert';
import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart';
import 'package:elliptic/ecdh.dart';
import 'package:elliptic/elliptic.dart';
import 'package:fido2/fido2.dart';
import 'package:test/test.dart';

import 'fido2_ctap.dart';
import 'support.dart';

void main() {
  setUpAll(initializeCrypto);
  group('PinProtocol V1', () {
    test('encapsulate', () async {
      final ec = getP256();
      final priv = ec.generatePrivateKey();
      final pub = priv.publicKey;
      final pubBytes = hex.decode(pub.toHex().substring(2));
      final peerCoseKey = EcdhEsHkdf256.fromPublicKey(
          pubBytes.sublist(0, 32), pubBytes.sublist(32, 64));

      PinProtocolV1 pinProtocol = PinProtocolV1();
      EncapsulateResult result = await pinProtocol.encapsulate(peerCoseKey);
      final sharedSecretX = computeSecret(
          priv,
          ec.hexToPublicKey(
              '04${hex.encode(result.coseKey[-2] + result.coseKey[-3])}'));
      final sharedSecret = await Sha256().hash(sharedSecretX);
      expect(sharedSecret.bytes, equals(result.sharedSecret));
    });

    test('encrypt', () async {
      final key = hex.decode(
          '000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f');
      final plaintext = hex.decode('00112233445566778899aabbccddeeff');
      final ciphertext = hex.decode('04a121e92033c921048917754f961b0d');
      PinProtocolV1 pinProtocol = PinProtocolV1();
      expect(await pinProtocol.encrypt(key, plaintext), equals(ciphertext));
    });

    test('decrypt', () async {
      final key = hex.decode(
          '000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f');
      final plaintext = hex.decode('00112233445566778899aabbccddeeff');
      final ciphertext = hex.decode('04a121e92033c921048917754f961b0d');
      PinProtocolV1 pinProtocol = PinProtocolV1();
      expect(await pinProtocol.decrypt(key, ciphertext), equals(plaintext));
    });

    test('authenticate', () async {
      final key = hex.decode('000102030405060708090a0b0c0d0e0f');
      final message = hex.decode('00112233445566778899aabbccddeeff');
      final signature = hex.decode(
          '32cd28477b88c12e515b0e1fd7330d19616a4a51f6c502d64fe6a93fe7f786fa');
      PinProtocolV1 pinProtocol = PinProtocolV1();
      expect(await pinProtocol.authenticate(key, message), equals(signature));
    });

    test('verify', () async {
      final key = hex.decode('000102030405060708090a0b0c0d0e0f');
      final message = hex.decode('00112233445566778899aabbccddeeff');
      final signature = hex.decode(
          '32cd28477b88c12e515b0e1fd7330d19616a4a51f6c502d64fe6a93fe7f786fa');
      final signatureFalse = hex.decode(
          '32cd28477b88c12e515b0e1fd7330d19616a4a51f6c502d64fe6a93fe7f786fb');
      PinProtocolV1 pinProtocol = PinProtocolV1();
      expect(await pinProtocol.verify(key, message, signature), equals(true));
      expect(await pinProtocol.verify(key, message, signatureFalse),
          equals(false));
    });
  });

  group('PinProtocol V2', () {
    final protocol = PinProtocolV2();
    test('ECDH and both HKDF keys match independent Dart implementation',
        () async {
      final ec = getP256();
      final private = ec.generatePrivateKey();
      final public = hex.decode(private.publicKey.toHex().substring(2));
      final result = await protocol.encapsulate(EcdhEsHkdf256.fromPublicKey(
          public.sublist(0, 32), public.sublist(32)));
      final secret = computeSecret(
          private,
          ec.hexToPublicKey(
              '04${hex.encode(result.coseKey[-2] + result.coseKey[-3])}'));
      final hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
      final expected = <int>[];
      for (final label in ['CTAP2 HMAC key', 'CTAP2 AES key']) {
        final key = await hkdf.deriveKey(
            secretKey: SecretKeyData(secret),
            nonce: List.filled(32, 0),
            info: ascii.encode(label));
        expected.addAll(key.bytes);
      }
      expect(result.sharedSecret, expected);
    });
    test('random IV, AES, HMAC, wire truncation and invalid lengths', () async {
      final key = List.generate(64, (i) => i);
      final plain = List<int>.filled(32, 0)..[0] = 42;
      final encrypted = await protocol.encrypt(key, plain);
      expect(encrypted, hasLength(48));
      expect(await protocol.decrypt(key, encrypted), plain);
      final reference = AesCbc.with256bits(
          macAlgorithm: MacAlgorithm.empty,
          paddingAlgorithm: PaddingAlgorithm.zero);
      expect(
          await reference.decrypt(
              SecretBox(encrypted.sublist(16),
                  nonce: encrypted.sublist(0, 16), mac: Mac.empty),
              secretKey: SecretKeyData(key.sublist(32))),
          plain);
      final expected = await Hmac.sha256()
          .calculateMac(plain, secretKey: SecretKeyData(key.sublist(0, 32)));
      expect(await protocol.authenticate(key, plain), expected.bytes);
      expect(await protocol.verify(key, plain, expected.bytes), isTrue);
      expect(await protocol.verify(key, plain, expected.bytes.sublist(1)),
          isFalse);
      expect(await protocol.authenticateParam(key, plain), hasLength(32));
      expect(await PinProtocolV1().authenticateParam(key.sublist(0, 32), plain),
          hasLength(16));
      await expectLater(
          protocol.encrypt(key.sublist(1), plain), throwsArgumentError);
      await expectLater(protocol.decrypt(key, [1]), throwsArgumentError);
      await expectLater(
          protocol.encrypt(key, [1]), throwsA(isA<CryptoException>()));
    });
  });

  group('ClientPin', () {
    test('Constructor', () async {
      MockDevice device = MockDevice();
      Ctap2 ctap2 = await Ctap2.create(device);
      ClientPin cp = ClientPin(ctap2);
      expect(cp.pinProtocolVersion, 1);
    });
  });
}
