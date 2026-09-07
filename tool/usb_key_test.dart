import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:cbor/cbor.dart';
import 'package:dart_pcsc/dart_pcsc.dart';
import 'package:fido2/fido2.dart';

/// Read-only by default. --sign creates non-resident test credentials and assertions.
class UsbCcid extends CtapDevice {
  final Card card;
  UsbCcid(this.card);
  @override
  Future<CtapResponse<List<int>>> transceive(List<int> command) async {
    final lc = command.length <= 255
        ? [command.length]
        : [0, command.length >> 8, command.length & 255];
    var apdu = [0x80, 0x10, 0, 0, ...lc, ...command];
    final data = <int>[];
    for (var part = 0; part < 256; part++) {
      final response = await card.transmit(Uint8List.fromList(apdu));
      if (response.length < 2) throw const FormatException('Truncated APDU');
      final sw1 = response[response.length - 2];
      final sw2 = response.last;
      data.addAll(response.sublist(0, response.length - 2));
      if (sw1 == 0x61) {
        apdu = [0x80, 0xc0, 0, 0, sw2];
        continue;
      }
      if (sw1 != 0x90 || sw2 != 0) {
        throw StateError('APDU status ${((sw1 << 8) | sw2).toRadixString(16)}');
      }
      if (data.isEmpty) throw const FormatException('Missing CTAP status');
      return CtapResponse(data.first, data.sublist(1));
    }
    throw StateError('Too many response fragments');
  }
}

Future<void> main(List<String> args) async {
  final library = Platform.isMacOS
      ? 'libfido2_crypto.dylib'
      : Platform.isWindows
      ? 'fido2_crypto.dll'
      : 'libfido2_crypto.so';
  await RustCrypto.initialize(
    libraryPath: File('build/fido2/native/release/$library').absolute.path,
  );
  final context = Context(Scope.user);
  Card? card;
  await context.establish();
  try {
    final readers = await context.listReaders();
    stdout.writeln('Readers: ${jsonEncode(readers)}');
    final reader =
        args.where((a) => !a.startsWith('--')).firstOrNull ?? readers.single;
    card = await context.connect(reader, ShareMode.shared, Protocol.any);
    final selected = await card.transmit(
      Uint8List.fromList([0, 0xa4, 4, 0, 8, 0xa0, 0, 0, 6, 0x47, 0x2f, 0, 1]),
    );
    if (selected.length < 2 ||
        selected[selected.length - 2] != 0x90 ||
        selected.last != 0) {
      throw StateError('FIDO applet selection failed');
    }
    stdout.writeln(
      'FIDO applet: ${ascii.decode(selected.sublist(0, selected.length - 2))}',
    );
    final device = UsbCcid(card);
    final info = await device.transceive([4]);
    if (info.status != 0) throw CtapError.fromCode(info.status);
    final raw = cbor.decode(info.data).toObject() as Map;
    stdout.writeln('Algorithms: ${jsonEncode(raw[10])}');
    stdout.writeln('Versions: ${jsonEncode(raw[1])}');
    stdout.writeln('Options: ${jsonEncode(raw[4])}');
    final ctap = await Ctap2.create(device);
    stdout.writeln('Parsed algorithms: ${jsonEncode(ctap.info.algorithms)}');
    for (final version in ctap.info.pinUvAuthProtocols ?? <int>[]) {
      final response = await ctap.clientPin(
        ClientPinRequest(pinUvAuthProtocol: version, subCommand: 2),
      );
      if (response.status != 0) throw CtapError.fromCode(response.status);
      final key = response.data!.keyAgreement!;
      key.validate();
      final protocol = version == 1 ? PinProtocolV1() : PinProtocolV2();
      final encapsulated = await protocol.encapsulate(key);
      stdout.writeln(
        'PIN v$version: device P-256 key valid; Rust ECDH/KDF produced ${encapsulated.sharedSecret.length} bytes',
      );
      final pin = ClientPin(ctap, pinProtocol: protocol);
      stdout.writeln('PIN v$version retries: ${await pin.getPinRetries()}');
    }
    stdout.writeln('Read-only hardware smoke test passed');
    if (args.contains('--sign')) {
      final selection = args
          .where((a) => a.startsWith('--algorithm='))
          .firstOrNull;
      final algorithms = selection == null
          ? [-7, -8, -49]
          : [int.parse(selection.split('=').last)];
      final profile = args.contains('--canokey-sm2')
          ? CoseConfiguration(
              sm2: Sm2Configuration(
                algorithm: -54,
                curve: 9,
                allowUnassignedIdentifiers: true,
              ),
            )
          : null;
      for (final algorithm in algorithms) {
        await signatureTest(device, algorithm, configuration: profile);
      }
    }
  } finally {
    await card?.disconnect(Disposition.leaveCard);
    await context.release();
  }
}

Future<void> signatureTest(
  UsbCcid device,
  int algorithm, {
  CoseConfiguration? configuration,
}) async {
  const rp = 'usb-test.fido2.local';
  const origin = 'https://usb-test.fido2.local';
  String b64(List<int> bytes) => base64Url.encode(bytes).replaceAll('=', '');
  Future<CborMap> send(int command, Map<int, dynamic> map) async {
    final result = await device.transceive([
      command,
      ...cbor.encode(CborValue(map)),
    ]);
    if (result.status != 0) throw CtapError.fromCode(result.status);
    return cbor.decode(result.data) as CborMap;
  }

  final challenge = RustCrypto.randomBytes(32);
  final clientCreate = utf8.encode(
    jsonEncode({
      'type': 'webauthn.create',
      'challenge': b64(challenge),
      'origin': origin,
    }),
  );
  stdout.writeln(
    'Algorithm $algorithm: creating non-resident credential; touch the key',
  );
  final created = await send(1, {
    1: CborBytes(RustCrypto.sha256(clientCreate)),
    2: {'id': rp, 'name': 'Local USB interoperability test'},
    3: {
      'id': CborBytes(RustCrypto.randomBytes(16)),
      'name': 'usb-test',
      'displayName': 'USB test',
    },
    4: [
      {'alg': algorithm, 'type': 'public-key'},
    ],
    7: {'rk': false},
  });
  final registeredData = AuthenticatorData.parse(
    (created[CborSmallInt(2)] as CborBytes).bytes,
    configuration: configuration,
  );
  final key = registeredData.credentialPublicKey!;
  if (key.algorithmId != algorithm) throw StateError('Unrequested algorithm');
  key.validate();
  final id = registeredData.credentialId!;
  final clientGet = utf8.encode(
    jsonEncode({
      'type': 'webauthn.get',
      'challenge': b64(challenge),
      'origin': origin,
    }),
  );
  stdout.writeln(
    'Algorithm $algorithm: credential parsed (${key.publicKeyBytes.length} public-key bytes); requesting assertion; touch the key',
  );
  final assertion = await send(2, {
    1: rp,
    2: CborBytes(RustCrypto.sha256(clientGet)),
    3: [
      {'type': 'public-key', 'id': CborBytes(id)},
    ],
    5: {'up': true},
  });
  final auth = (assertion[CborSmallInt(2)] as CborBytes).bytes;
  final sig = (assertion[CborSmallInt(3)] as CborBytes).bytes;
  final server = Fido2Server(
    Fido2Config(
      rpId: rp,
      origins: {origin},
      signatureAlgorithms: [algorithm],
      cose: configuration,
    ),
  );
  final count = server.authenticateComplete(
    {
      'id': b64(id),
      'rawId': b64(id),
      'type': 'public-key',
      'response': {
        'clientDataJSON': b64(clientGet),
        'authenticatorData': b64(auth),
        'signature': b64(sig),
      },
    },
    credential: RegisteredCredential(
      id: id,
      publicKey: key,
      signCount: registeredData.signCount,
      backupEligible: registeredData.backupEligible,
    ),
    expectedChallenge: challenge,
  );
  stdout.writeln(
    'PASS algorithm $algorithm: ${sig.length}-byte device signature verified by Rust/WebAuthn; counter $count; attestation trust not evaluated',
  );
}
