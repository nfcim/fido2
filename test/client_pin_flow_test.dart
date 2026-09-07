import 'dart:convert';
import 'package:cbor/cbor.dart';
import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart';
import 'package:elliptic/ecdh.dart';
import 'package:elliptic/elliptic.dart';
import 'package:fido2/fido2.dart';
import 'package:test/test.dart';
import 'support.dart';

class PinDevice extends CtapDevice {
  final int version;
  final private = getP256().generatePrivateKey();
  final token = List<int>.filled(32, 123);
  String pin = '';
  PinDevice(this.version);

  CtapResponse<List<int>> reply(Map<int, dynamic> map) =>
      CtapResponse(0, cbor.encode(CborValue(map)));

  @override
  Future<CtapResponse<List<int>>> transceive(List<int> command) async {
    if (command.first == 4) {
      return reply({
        1: ['FIDO_2_0'],
        3: CborBytes(List.filled(16, 0)),
        4: {'clientPin': true},
        6: [version]
      });
    }
    expect(command.first, 6);
    final request = cbor.decode(command.sublist(1)).toObject() as Map;
    expect(request[1], version);
    if (request[2] == 2) {
      final public = hex.decode(private.publicKey.toHex().substring(2));
      return reply({
        1: EcdhEsHkdf256.fromPublicKey(
                public.sublist(0, 32), public.sublist(32))
            .toCbor()
      });
    }
    final peer = request[3] as Map;
    final z = computeSecret(
        private,
        getP256().hexToPublicKey(
            '04${hex.encode((peer[-2] as List).cast<int>() + (peer[-3] as List).cast<int>())}'));
    final shared = <int>[];
    if (version == 1) {
      shared.addAll((await Sha256().hash(z)).bytes);
    } else {
      final hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
      for (final label in ['CTAP2 HMAC key', 'CTAP2 AES key']) {
        shared.addAll((await hkdf.deriveKey(
                secretKey: SecretKeyData(z),
                nonce: List.filled(32, 0),
                info: ascii.encode(label)))
            .bytes);
      }
    }
    final protocol = version == 1 ? PinProtocolV1() : PinProtocolV2();
    if (request[2] == 4 || request[2] == 5) {
      final actual =
          await protocol.decrypt(shared, (request[6] as List).cast<int>());
      expect(
          actual, (await Sha256().hash(utf8.encode(pin))).bytes.sublist(0, 16));
    }
    if (request[2] == 5) {
      return reply({2: CborBytes(await protocol.encrypt(shared, token))});
    }
    final encrypted = (request[5] as List).cast<int>();
    final msg = [
      ...encrypted,
      if (request[2] == 4) ...(request[6] as List).cast<int>()
    ];
    final mac = await Hmac.sha256()
        .calculateMac(msg, secretKey: SecretKeyData(shared.sublist(0, 32)));
    expect(request[4], version == 1 ? mac.bytes.sublist(0, 16) : mac.bytes);
    final plain = await protocol.decrypt(shared, encrypted);
    expect(plain, hasLength(64));
    pin = utf8.decode(plain.takeWhile((b) => b != 0).toList());
    return CtapResponse(0, []);
  }
}

void main() {
  setUpAll(initializeCrypto);
  for (final version in [1, 2]) {
    test('PIN v$version set, change and token CTAP exchanges', () async {
      final device = PinDevice(version);
      final client = ClientPin(await Ctap2.create(device));
      await client.setPin('123456');
      expect(device.pin, '123456');
      await client.changePin('123456', '654321');
      expect(device.pin, '654321');
      expect(await client.getPinToken('654321'), device.token);
    });
  }
}
