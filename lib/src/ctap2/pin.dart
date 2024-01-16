import 'dart:convert';

import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart';
import 'package:cryptography/helpers.dart';
import 'package:elliptic/ecdh.dart';
import 'package:elliptic/elliptic.dart';
import 'package:fido2/fido2.dart';
import 'package:fido2/src/cose.dart';
import 'package:quiver/collection.dart';

class EncapsulateResult {
  final CoseKey coseKey;
  final List<int> sharedSecret;

  EncapsulateResult(this.coseKey, this.sharedSecret);
}

abstract class PinProtocol {
  int get version;

  Future<EncapsulateResult> encapsulate(CoseKey peerCoseKey);

  Future<List<int>> encrypt(List<int> key, List<int> plaintext);

  Future<List<int>> decrypt(List<int> key, List<int> ciphertext);

  Future<List<int>> authenticate(List<int> key, List<int> message);

  Future<bool> verify(List<int> key, List<int> message, List<int> signature);
}

class PinProtocolV1 extends PinProtocol {
  @override
  int get version => 1;

  final _aes = AesCbc.with128bits(
      macAlgorithm: MacAlgorithm.empty,
      paddingAlgorithm: PaddingAlgorithm.zero);

  Future<List<int>> _kdf(List<int> z) async {
    return (await Sha256().hash(z)).bytes;
  }

  @override
  Future<EncapsulateResult> encapsulate(CoseKey peerCoseKey) async {
    final ec = getP256();
    final priv = ec.generatePrivateKey();
    final pub = priv.publicKey;
    final pubBytes = hex.decode(pub.toHex().substring(2));
    final keyAgreement = EcdhEsHkdf256.fromPublicKey(
        pubBytes.sublist(0, 32), pubBytes.sublist(32, 64));
    final sharedSecretX = computeSecret(
        priv,
        ec.hexToPublicKey(
            '04${hex.encode(peerCoseKey[-2] + peerCoseKey[-3])}'));
    final sharedSecret = await _kdf(sharedSecretX);
    return EncapsulateResult(keyAgreement, sharedSecret);
  }

  @override
  Future<List<int>> encrypt(List<int> key, List<int> plaintext) async {
    final secretBox = await _aes.encrypt(plaintext,
        secretKey: SecretKeyData(key), nonce: List.filled(16, 0));
    return secretBox.cipherText;
  }

  @override
  Future<List<int>> decrypt(List<int> key, List<int> ciphertext) async {
    return await _aes.decrypt(
        SecretBox(ciphertext, nonce: List.filled(16, 0), mac: Mac.empty),
        secretKey: SecretKeyData(key));
  }

  @override
  Future<List<int>> authenticate(List<int> key, List<int> message) async {
    final mac = await Hmac.sha256()
        .calculateMac(message, secretKey: SecretKeyData(key));
    return mac.bytes;
  }

  @override
  Future<bool> verify(
      List<int> key, List<int> message, List<int> signature) async {
    final mac = await Hmac.sha256()
        .calculateMac(message, secretKey: SecretKeyData(key));
    return listsEqual(mac.bytes, signature);
  }
}

class PinProtocolV2 extends PinProtocolV1 {
  static final List<int> _hkdfSalt = List.filled(32, 0);
  static final String _hkdfInfoHmac = 'CTAP2 HMAC key';
  static final String _hkdfInfoAes = 'CTAP2 AES key';

  @override
  int get version => 2;

  final _aes = AesCbc.with128bits(
      macAlgorithm: MacAlgorithm.empty,
      paddingAlgorithm: PaddingAlgorithm.zero);

  @override
  Future<List<int>> _kdf(List<int> z) async {
    final algorithm = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
    final hmacKey = await algorithm.deriveKey(
        secretKey: SecretKeyData(z),
        nonce: _hkdfSalt,
        info: ascii.encode(_hkdfInfoHmac));
    final aesKey = await algorithm.deriveKey(
        secretKey: SecretKeyData(z),
        nonce: _hkdfSalt,
        info: ascii.encode(_hkdfInfoAes));
    return hmacKey.bytes + aesKey.bytes;
  }

  @override
  Future<List<int>> encrypt(List<int> key, List<int> plaintext) async {
    final aesKey = key.sublist(32);
    final iv = randomBytes(16);
    final secretBox = await _aes.encrypt(plaintext,
        secretKey: SecretKeyData(aesKey), nonce: iv);
    return iv + secretBox.cipherText;
  }

  @override
  Future<List<int>> decrypt(List<int> key, List<int> ciphertext) async {
    final aesKey = key.sublist(32);
    final iv = ciphertext.sublist(0, 16);
    final cipherText = ciphertext.sublist(16);
    return await _aes.decrypt(SecretBox(cipherText, nonce: iv, mac: Mac.empty),
        secretKey: SecretKeyData(aesKey));
  }

  @override
  Future<List<int>> authenticate(List<int> key, List<int> message) async {
    final hmacKey = key.sublist(0, 32);
    final mac = await Hmac.sha256()
        .calculateMac(message, secretKey: SecretKeyData(hmacKey));
    return mac.bytes;
  }

  @override
  Future<bool> verify(
      List<int> key, List<int> message, List<int> signature) async {
    final hmacKey = key.sublist(0, 32);
    final mac = await Hmac.sha256()
        .calculateMac(message, secretKey: SecretKeyData(hmacKey));
    return listsEqual(mac.bytes, signature);
  }
}

enum ClientPinSubCommand {
  getPinRetries(0x01),
  getKeyAgreement(0x02),
  setPin(0x03),
  changePin(0x04),
  getPinToken(0x05),
  getPinUvAuthTokenUsingUvWithPermissions(0x06),
  getUvRetries(0x07),
  getPinUvAuthTokenUsingPinWithPermissions(0x08);

  const ClientPinSubCommand(this.value);

  final int value;
}

enum ClientPinPermission {
  makeCredential(0x01),
  getAssertion(0x02),
  credentialManagement(0x04),
  bioEnrollment(0x08),
  largeBlobWrite(0x10),
  authenticatorConfig(0x20);

  const ClientPinPermission(this.value);

  final int value;
}

class ClientPin {
  final Ctap2 _ctap;
  late final PinProtocol _pinProtocol;

  get pinProtocolVersion => _pinProtocol.version;

  ClientPin._create(this._ctap);

  static Future<ClientPin> create(Ctap2 ctap,
      {PinProtocol? pinProtocol}) async {
    var cp = ClientPin._create(ctap);
    if (pinProtocol != null) {
      cp._pinProtocol = pinProtocol;
      return cp;
    }

    var res = await ctap.getInfo();
    if (res.status != 0) {
      throw Exception('GetInfo failed.');
    }
    if (res.data.pinUvAuthProtocols != null) {
      if (res.data.pinUvAuthProtocols![0] == 1) {
        cp._pinProtocol = PinProtocolV1();
      } else if (res.data.pinUvAuthProtocols![0] == 2) {
        cp._pinProtocol = PinProtocolV2();
      } else {
        throw Exception('Unknown pinUvAuthProtocol.');
      }
    } else {
      cp._pinProtocol = PinProtocolV1();
    }

    return cp;
  }
}
