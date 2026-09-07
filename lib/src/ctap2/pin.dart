import 'entities/authenticator_info.dart';
import 'requests/client_pin.dart';
import '../utils/serialization.dart';
import 'package:json_annotation/json_annotation.dart';
import 'dart:convert';

import '../cose.dart';
import '../ctap.dart';
import '../crypto/crypto.dart';
import 'base.dart';

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

  /// CTAP wire MAC: v1 transmits 16 bytes, v2 transmits 32. The existing
  /// [authenticate] API continues to return the full HMAC for compatibility.
  Future<List<int>> authenticateParam(List<int> key, List<int> message) async {
    final mac = await authenticate(key, message);
    return version == 1 ? mac.sublist(0, 16) : mac;
  }

  Future<bool> verify(List<int> key, List<int> message, List<int> signature);
}

class PinProtocolV1 extends PinProtocol {
  @override
  int get version => 1;

  @override
  Future<EncapsulateResult> encapsulate(CoseKey peerCoseKey) async {
    if (peerCoseKey[1] != 2 || peerCoseKey[3] != -25 || peerCoseKey[-1] != 1) {
      throw ArgumentError('Expected a P-256 ECDH key');
    }
    final result = RustCrypto.encapsulatePin([
      4,
      ...List<int>.from(peerCoseKey[-2]),
      ...List<int>.from(peerCoseKey[-3]),
    ], version);
    final keyAgreement = EcdhEsHkdf256.fromPublicKey(
      result.sublist(1, 33),
      result.sublist(33, 65),
    );
    return EncapsulateResult(keyAgreement, result.sublist(65));
  }

  @override
  Future<List<int>> encrypt(List<int> key, List<int> plaintext) async {
    return RustCrypto.aes256Cbc(key, plaintext, iv: List.filled(16, 0));
  }

  @override
  Future<List<int>> decrypt(List<int> key, List<int> ciphertext) async {
    return RustCrypto.aes256Cbc(
      key,
      ciphertext,
      iv: List.filled(16, 0),
      decrypt: true,
    );
  }

  @override
  Future<List<int>> authenticate(List<int> key, List<int> message) async {
    return RustCrypto.hmacSha256(key, message);
  }

  @override
  Future<bool> verify(
    List<int> key,
    List<int> message,
    List<int> signature,
  ) async {
    return RustCrypto.verifyHmacSha256(key, message, signature);
  }
}

class PinProtocolV2 extends PinProtocolV1 {
  @override
  int get version => 2;

  @override
  Future<List<int>> encrypt(List<int> key, List<int> plaintext) async {
    if (key.length != 64) throw ArgumentError('Expected 64-byte v2 key');
    final iv = RustCrypto.randomBytes(16);
    return iv + RustCrypto.aes256Cbc(key.sublist(32), plaintext, iv: iv);
  }

  @override
  Future<List<int>> decrypt(List<int> key, List<int> ciphertext) async {
    if (key.length != 64 || ciphertext.length < 16) {
      throw ArgumentError('Invalid v2 key or ciphertext length');
    }
    final iv = ciphertext.sublist(0, 16);
    final cipherText = ciphertext.sublist(16);
    return RustCrypto.aes256Cbc(
      key.sublist(32),
      cipherText,
      iv: iv,
      decrypt: true,
    );
  }

  @override
  Future<List<int>> authenticate(List<int> key, List<int> message) async {
    if (key.length != 32 && key.length != 64) {
      throw ArgumentError('Expected a v2 token or shared secret');
    }
    return RustCrypto.hmacSha256(key.sublist(0, 32), message);
  }

  @override
  Future<bool> verify(
    List<int> key,
    List<int> message,
    List<int> signature,
  ) async {
    if (key.length != 32 && key.length != 64) {
      throw ArgumentError('Expected a v2 token or shared secret');
    }
    return RustCrypto.verifyHmacSha256(key.sublist(0, 32), message, signature);
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
    final resp = await _ctap.clientPin(
      ClientPinRequest(
        pinUvAuthProtocol: _pinProtocol.version,
        subCommand: ClientPinSubCommand.getKeyAgreement.value,
      ),
    );
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
  Future<List<int>> getPinToken(
    String pin, {
    List<ClientPinPermission>? permissions,
    String? permissionsRpId,
  }) async {
    if (!ClientPin.isSupported(_ctap.info)) {
      throw Exception('getPinToken is not supported.');
    }

    final EncapsulateResult ss = await _getSharedSecret();
    final pinHash = RustCrypto.sha256(utf8.encode(pin)).sublist(0, 16);
    final pinHashEnc = await _pinProtocol.encrypt(ss.sharedSecret, pinHash);

    int subCmd = ClientPinSubCommand.getPinToken.value;
    if (ClientPin.isPinUvAuthTokenSupported(_ctap.info)) {
      assert(permissions != null);
      subCmd =
          ClientPinSubCommand.getPinUvAuthTokenUsingPinWithPermissions.value;
    }

    final resp = await _ctap.clientPin(
      ClientPinRequest(
        pinUvAuthProtocol: _pinProtocol.version,
        subCommand: subCmd,
        keyAgreement: ss.coseKey,
        pinHashEnc: pinHashEnc,
        permissions: permissions?.fold(0, (p, e) => p! | e.value),
        rpId: permissionsRpId,
      ),
    );

    if (resp.status != 0) {
      throw CtapError.fromCode(resp.status);
    }

    return await _pinProtocol.decrypt(
      ss.sharedSecret,
      resp.data!.pinUvAuthToken!,
    );
  }

  /// Get the number of PIN retries remaining.
  Future<int> getPinRetries() async {
    if (!ClientPin.isSupported(_ctap.info)) {
      throw Exception('getPinRetries is not supported.');
    }

    final resp = await _ctap.clientPin(
      ClientPinRequest(
        pinUvAuthProtocol: _pinProtocol.version,
        subCommand: ClientPinSubCommand.getPinRetries.value,
      ),
    );
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
    final pinUvAuthParam = await _pinProtocol.authenticateParam(
      ss.sharedSecret,
      pinEnc,
    );
    final resp = await _ctap.clientPin(
      ClientPinRequest(
        pinUvAuthProtocol: _pinProtocol.version,
        subCommand: ClientPinSubCommand.setPin.value,
        keyAgreement: ss.coseKey,
        newPinEnc: pinEnc,
        pinUvAuthParam: pinUvAuthParam,
      ),
    );

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
    final pinHash = RustCrypto.sha256(utf8.encode(oldPin)).sublist(0, 16);
    final pinHashEnc = await _pinProtocol.encrypt(ss.sharedSecret, pinHash);
    final newPinEnc = await _pinProtocol.encrypt(
      ss.sharedSecret,
      _padPin(newPin),
    );
    final pinUvAuthParam = await _pinProtocol.authenticateParam(
      ss.sharedSecret,
      newPinEnc + pinHashEnc,
    );
    final resp = await _ctap.clientPin(
      ClientPinRequest(
        pinUvAuthProtocol: _pinProtocol.version,
        subCommand: ClientPinSubCommand.changePin.value,
        keyAgreement: ss.coseKey,
        pinHashEnc: pinHashEnc,
        newPinEnc: newPinEnc,
        pinUvAuthParam: pinUvAuthParam,
      ),
    );

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
