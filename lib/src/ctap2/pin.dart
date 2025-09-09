import 'dart:convert';

import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart';
import 'package:cryptography/helpers.dart';
import 'package:elliptic/ecdh.dart';
import 'package:elliptic/elliptic.dart';
import 'package:fido2/src/cose.dart';
import 'package:fido2/src/ctap.dart';
import 'package:fido2/src/ctap2/base.dart';
import 'package:fido2/src/ctap2/entities/authenticator_info.dart';
import 'package:fido2/src/ctap2/requests/client_pin.dart';
import 'package:quiver/collection.dart';
import 'package:fido2/src/utils/serialization.dart';
import 'package:json_annotation/json_annotation.dart';

part 'pin.g.dart';

@JsonSerializable(createFactory: false, explicitToJson: true)
class EncapsulateResult with JsonToStringMixin {
  final CoseKey coseKey;
  final List<int> sharedSecret;

  EncapsulateResult(this.coseKey, this.sharedSecret);

  @override
  Map<String, dynamic> toJson() => _$EncapsulateResultToJson(this);
}

sealed class PinProtocol {
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

  final _aes = AesCbc.with256bits(
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
  getPinUvAuthTokenUsingPinWithPermissions(0x09);

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

  int get pinProtocolVersion => _pinProtocol.version;

  ClientPin(this._ctap, {PinProtocol? pinProtocol}) {
    if (pinProtocol != null) {
      _pinProtocol = pinProtocol;
      return;
    }

    // detect pin protocol version from authenticator info
    if (_ctap.info.pinUvAuthProtocols != null) {
      if (_ctap.info.pinUvAuthProtocols![0] == 1) {
        _pinProtocol = PinProtocolV1();
      } else if (_ctap.info.pinUvAuthProtocols![0] == 2) {
        _pinProtocol = PinProtocolV2();
      } else {
        throw Exception('Unknown pinUvAuthProtocol.');
      }
    } else {
      _pinProtocol = PinProtocolV1();
    }
  }

  /// Returns true if the authenticator [info] supports the ClientPin command.
  static bool isSupported(AuthenticatorInfo info) {
    return info.options?.containsKey('clientPin') ?? false;
  }

  /// Returns true if the authenticator [info] supports the pinUvAuthToken option.
  static bool isPinUvAuthTokenSupported(AuthenticatorInfo info) {
    return info.options?.containsKey('pinUvAuthToken') ?? false;
  }

  Future<EncapsulateResult> _getSharedSecret() async {
    final resp = await _ctap.clientPin(ClientPinRequest(
        pinUvAuthProtocol: _pinProtocol.version,
        subCommand: ClientPinSubCommand.getKeyAgreement.value));
    if (resp.status != 0) {
      throw Exception('ClientPin failed.');
    }
    return _pinProtocol.encapsulate(resp.data!.keyAgreement!);
  }

  /// Get a PIN/UV token from the authenticator.
  ///
  /// [pin] is the PIN code.
  /// [permissions] is the permissions to be granted to the token.
  /// [permissionsRpId] is the RP ID to which the permissions apply.
  Future<List<int>> getPinToken(String pin,
      {List<ClientPinPermission>? permissions, String? permissionsRpId}) async {
    if (!ClientPin.isSupported(_ctap.info)) {
      throw Exception('getPinToken is not supported.');
    }

    final EncapsulateResult ss = await _getSharedSecret();
    final pinHash =
        (await Sha256().hash(utf8.encode(pin))).bytes.sublist(0, 16);
    final pinHashEnc = await _pinProtocol.encrypt(ss.sharedSecret, pinHash);

    int subCmd = ClientPinSubCommand.getPinToken.value;
    if (ClientPin.isPinUvAuthTokenSupported(_ctap.info)) {
      assert(permissions != null);
      subCmd =
          ClientPinSubCommand.getPinUvAuthTokenUsingPinWithPermissions.value;
    }

    final resp = await _ctap.clientPin(ClientPinRequest(
        pinUvAuthProtocol: _pinProtocol.version,
        subCommand: subCmd,
        keyAgreement: ss.coseKey,
        pinHashEnc: pinHashEnc,
        permissions: permissions?.fold(0, (p, e) => p! | e.value),
        rpId: permissionsRpId));

    if (resp.status != 0) {
      throw CtapError.fromCode(resp.status);
    }

    return await _pinProtocol.decrypt(
        ss.sharedSecret, resp.data!.pinUvAuthToken!);
  }

  /// Get the number of PIN retries remaining.
  Future<int> getPinRetries() async {
    if (!ClientPin.isSupported(_ctap.info)) {
      throw Exception('getPinRetries is not supported.');
    }

    final resp = await _ctap.clientPin(ClientPinRequest(
        pinUvAuthProtocol: _pinProtocol.version,
        subCommand: ClientPinSubCommand.getPinRetries.value));
    return resp.data!.pinRetries!;
  }

  /// Set the [pin] of the authenticator.
  ///
  ///  This only works when no PIN is set. To change the PIN when set, use changePin.
  Future<void> setPin(String pin) async {
    if (!ClientPin.isSupported(_ctap.info)) {
      throw Exception('setPin is not supported.');
    }

    final EncapsulateResult ss = await _getSharedSecret();
    final pinEnc = await _pinProtocol.encrypt(ss.sharedSecret, _padPin(pin));
    final pinUvAuthParam =
        await _pinProtocol.authenticate(ss.sharedSecret, pinEnc);
    final resp = await _ctap.clientPin(ClientPinRequest(
        pinUvAuthProtocol: _pinProtocol.version,
        subCommand: ClientPinSubCommand.setPin.value,
        keyAgreement: ss.coseKey,
        newPinEnc: pinEnc,
        pinUvAuthParam: pinUvAuthParam));

    if (resp.status != 0) {
      throw CtapError.fromCode(resp.status);
    }
  }

  /// Change the PIN of the authenticator.
  /// This only works when a PIN is already set. If no PIN is set, use setPin.
  Future<void> changePin(String oldPin, String newPin) async {
    if (!ClientPin.isSupported(_ctap.info)) {
      throw Exception('changePin is not supported.');
    }

    final EncapsulateResult ss = await _getSharedSecret();
    final pinHash =
        (await Sha256().hash(utf8.encode(oldPin))).bytes.sublist(0, 16);
    final pinHashEnc = await _pinProtocol.encrypt(ss.sharedSecret, pinHash);
    final newPinEnc =
        await _pinProtocol.encrypt(ss.sharedSecret, _padPin(newPin));
    final pinUvAuthParam = await _pinProtocol.authenticate(
        ss.sharedSecret, newPinEnc + pinHashEnc);
    final resp = await _ctap.clientPin(ClientPinRequest(
        pinUvAuthProtocol: _pinProtocol.version,
        subCommand: ClientPinSubCommand.changePin.value,
        keyAgreement: ss.coseKey,
        pinHashEnc: pinHashEnc,
        newPinEnc: newPinEnc,
        pinUvAuthParam: pinUvAuthParam));

    if (resp.status != 0) {
      throw CtapError.fromCode(resp.status);
    }
  }

  /// Pad the PIN to 64 bytes.
  List<int> _padPin(String pin) {
    final pinBytes = utf8.encode(pin);
    return pinBytes + List.filled(64 - pinBytes.length, 0);
  }
}
