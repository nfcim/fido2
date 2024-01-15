import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart';
import 'package:elliptic/ecdh.dart';
import 'package:elliptic/elliptic.dart';
import 'package:fido2/src/cose.dart';
import 'package:quiver/collection.dart';

class EncapsulateResult {
  final CoseKey coseKey;
  final List<int> sharedSecret;

  EncapsulateResult(this.coseKey, this.sharedSecret);
}

abstract class PinProtocol {
  Future<EncapsulateResult> encapsulate(CoseKey peerCoseKey);

  Future<List<int>> encrypt(List<int> key, List<int> plaintext);

  Future<List<int>> decrypt(List<int> key, List<int> ciphertext);

  Future<List<int>> authenticate(List<int> key, List<int> message);

  Future<bool> verify(List<int> key, List<int> message, List<int> signature);
}

class PinProtocolV1 extends PinProtocol {
  @override
  Future<EncapsulateResult> encapsulate(CoseKey peerCoseKey) async {
    final ec = getP256();
    final priv = ec.generatePrivateKey();
    final pub = priv.publicKey;
    final pubBytes = hex.decode(pub.toHex().substring(2));
    final keyAgreement = EcdhEsHkdf256.fromPublicKey(
        pubBytes.sublist(0, 32), pubBytes.sublist(32, 64));
    final sharedSecret = computeSecret(
        priv,
        ec.hexToPublicKey(
            '04${hex.encode(peerCoseKey[-2] + peerCoseKey[-3])}'));
    return EncapsulateResult(keyAgreement, sharedSecret);
  }

  @override
  Future<List<int>> encrypt(List<int> key, List<int> plaintext) async {
    final algorithm = AesCbc.with128bits(
        macAlgorithm: MacAlgorithm.empty,
        paddingAlgorithm: PaddingAlgorithm.zero);
    final secretBox = await algorithm.encrypt(plaintext,
        secretKey: SecretKeyData(key), nonce: List.filled(16, 0));
    return secretBox.cipherText;
  }

  @override
  Future<List<int>> decrypt(List<int> key, List<int> ciphertext) async {
    final algorithm = AesCbc.with128bits(
        macAlgorithm: MacAlgorithm.empty,
        paddingAlgorithm: PaddingAlgorithm.zero);
    return await algorithm.decrypt(
        SecretBox(ciphertext, nonce: List.filled(16, 0), mac: Mac.empty),
        secretKey: SecretKeyData(key));
  }

  @override
  Future<List<int>> authenticate(List<int> key, List<int> message) async {
    final algorithm = Hmac.sha256();
    final mac =
        await algorithm.calculateMac(message, secretKey: SecretKeyData(key));
    return mac.bytes;
  }

  @override
  Future<bool> verify(
      List<int> key, List<int> message, List<int> signature) async {
    final algorithm = Hmac.sha256();
    final mac =
        await algorithm.calculateMac(message, secretKey: SecretKeyData(key));
    return listsEqual(mac.bytes, signature);
  }
}
