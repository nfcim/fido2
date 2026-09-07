import 'dart:convert';
import 'dart:typed_data';

import 'package:cbor/cbor.dart';
import 'package:fido2/fido2_client.dart';
import 'package:fido2/fido2_server.dart';
import 'package:fido2/src/authenticator_data.dart' as legacy;
import 'package:test/test.dart';
import 'fido2_ctap.dart';
import 'support.dart';

void main() {
  setUpAll(initializeCrypto);

  test('CTAP configuration names and six static helpers', () async {
    final config = CoseConfiguration();
    final old = await Ctap2.create(MockDevice(), coseConfiguration: config);
    final current = await Ctap2.create(MockDevice(), configuration: config);
    expect(old.configuration, same(config));
    expect(current.coseConfiguration, same(config));
    await expectLater(
      Ctap2.create(
        MockDevice(),
        configuration: config,
        coseConfiguration: CoseConfiguration(),
      ),
      throwsArgumentError,
    );
    expect(Ctap2.makeGetInfoRequest(), [4]);
    final info = AuthenticatorInfo(
      versions: ['FIDO_2_1'],
      aaguid: List.filled(16, 1),
    );
    expect(Ctap2.parseGetInfoResponse(info.encode()).aaguid, info.aaguid);
    final pin = ClientPinRequest(subCommand: 1);
    expect(Ctap2.makeClientPinRequest(pin), pin.encode());
    expect(Ctap2.parseClientPinResponse([0xa1, 3, 8]).pinRetries, 8);
    final management = CredentialManagementRequest(subCommand: 1);
    expect(
      Ctap2.makeCredentialManagementRequest(management),
      management.encode(),
    );
    expect(
      Ctap2.parseCredentialManagementResponse([
        0xa1,
        1,
        2,
      ]).existingResidentCredentialsCount,
      2,
    );
  });

  test('getInfo AAGUID is a CBOR byte string', () {
    final info = AuthenticatorInfo(
      versions: ['FIDO_2_1'],
      aaguid: List.filled(16, 1),
    );
    final encoded = cbor.decode(info.encode()) as CborMap;
    expect(encoded[CborSmallInt(3)], isA<CborBytes>());
  });

  test('async verify and synchronous verifySync expose failures', () async {
    final key = EdDSA.fromPublicKey(List.filled(32, 0));
    final future = key.verify([], List.filled(64, 0));
    expect(future, isA<Future<void>>());
    await expectLater(future, throwsA(isA<CryptoException>()));
    expect(
      () => key.verifySync([], List.filled(64, 0)),
      throwsA(isA<CryptoException>()),
    );
  });

  test('old import and flat accessors use immutable parsed bytes', () {
    List<int> wire(CborMap key) => [
      ...List.filled(32, 0),
      0x41,
      0,
      0,
      0,
      0,
      ...List.filled(16, 7),
      0,
      1,
      42,
      ...cbor.encode(key),
    ];
    final input = wire(
      CborMap({
        CborSmallInt(1): CborSmallInt(99),
        CborSmallInt(3): CborSmallInt(-60000),
      }),
    );
    final parsed = legacy.AuthenticatorData.parse(input);
    input[0] = 1;
    expect(parsed.bytes[0], 0);
    expect(parsed.aaguid, List.filled(16, 7));
    expect(parsed.credentialId, [42]);
    expect(parsed.credentialPublicKey, isA<UnsupportedKey>());
    expect(() => parsed.bytes[0] = 1, throwsUnsupportedError);
    expect(() => parsed.rpIdHash[0] = 1, throwsUnsupportedError);
    expect(
      () => parsed.attestedCredentialData!.aaguid[0] = 1,
      throwsUnsupportedError,
    );
    expect(
      () => legacy.AuthenticatorData.parse(
        wire(CborMap({CborSmallInt(1): CborSmallInt(2)})),
      ),
      throwsFormatException,
    );
    final source = Uint8List(37);
    final constructed = AuthenticatorData(
      rpIdHash: Uint8List(32),
      flags: 0,
      signCount: 0,
      bytes: source,
    );
    source[0] = 1;
    expect(constructed.bytes[0], 0);
  });

  test('PIN shared secrets are excluded from JSON and string logs', () {
    final result = EncapsulateResult(EdDSA.fromPublicKey(List.filled(32, 0)), [
      123,
      234,
      45,
    ]);
    expect(result.sharedSecret, [123, 234, 45]);
    expect(result.toJson(), isNot(contains('sharedSecret')));
    expect(jsonDecode(result.toString()), isNot(contains('sharedSecret')));
    expect(result.toString(), isNot(contains('234')));
  });

  test('origin defaults and explicit allowlists', () {
    expect(Fido2Config(rpId: 'example.com').origins, {'https://example.com'});
    final origins = {'https://login.example.com'};
    final config = Fido2Config(rpId: 'example.com', origins: origins);
    origins.add('https://example.com');
    expect(config.origins, {'https://login.example.com'});
    expect(
      () => Fido2Config(rpId: 'example.com', origins: {}),
      throwsArgumentError,
    );
  });
}
