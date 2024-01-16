import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart';
import 'package:elliptic/ecdh.dart';
import 'package:elliptic/elliptic.dart';
import 'package:fido2/fido2.dart';
import 'package:test/test.dart';

import 'fido2_ctap.dart';

void main() {
  group('Protocol 1', () {
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

  group('Protocol 2', () {});

  group('ClientPin', () {
    test('Constructor', () async {
      MockDevice device = MockDevice();
      Ctap2 ctap2 = await Ctap2.create(device);
      ClientPin cp = ClientPin(ctap2);
      expect(cp.pinProtocolVersion, 1);
    });
  });
}
