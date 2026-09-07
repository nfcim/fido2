import 'package:cbor/cbor.dart';
import 'package:fido2/fido2.dart';
import 'package:test/test.dart';
import 'support.dart';

void main() {
  setUpAll(initializeCrypto);
  final rpIdHash = List<int>.generate(32, (index) => index);
  final pinToken = List<int>.generate(32, (index) => 0xa0 + index);

  test(
    'metadata-only Begin is authenticated and GetNext has no params',
    () async {
      final device = _CredentialManagementDevice([
        _credentialResponse(
          userId: [1],
          coseAlgorithm: -49,
          totalCredentials: 2,
          metadataOnly: true,
        ),
        _credentialResponse(userId: [2], coseAlgorithm: -8, metadataOnly: true),
      ]);
      final ctap = await Ctap2.create(device);
      final pinProtocol = PinProtocolV1();
      final manager = CredentialManagement(ctap, pinProtocol, pinToken);

      final credentials = await manager.enumerateCredentialsMetadataOnly(
        rpIdHash,
      );

      expect(credentials, hasLength(2));
      expect(credentials[0].coseAlgorithm, -49);
      expect(credentials[0].metadataOnly, isTrue);
      expect(credentials[0].publicKey, isNull);
      expect(credentials[1].coseAlgorithm, -8);

      final begin = _decodeRequest(device.commands[1]);
      expect(begin[1], 0x04);
      final params = (begin[2] as Map).cast<int, dynamic>();
      expect(params, {1: rpIdHash, 0x80: true});
      expect(begin[3], 1);

      final canonicalParams = CborMap({
        const CborSmallInt(1): CborBytes(rpIdHash),
        const CborSmallInt(0x80): const CborBool(true),
      });
      final authenticationMessage = <int>[
        0x04,
        ...cbor.encode(canonicalParams),
      ];
      expect(
        begin[4],
        (await pinProtocol.authenticate(
          pinToken,
          authenticationMessage,
        )).sublist(0, 16),
      );

      final getNext = _decodeRequest(device.commands[2]);
      expect(getNext.containsKey(2), isFalse);
      expect(getNext[1], 0x05);
    },
  );

  test('metadata enumeration accepts a standard public-key response', () async {
    final device = _CredentialManagementDevice([
      _credentialResponse(
        userId: [3],
        coseAlgorithm: -7,
        totalCredentials: 1,
        metadataOnly: false,
      ),
    ]);
    final ctap = await Ctap2.create(device);
    final manager = CredentialManagement(ctap, PinProtocolV1(), pinToken);

    final credentials = await manager.enumerateCredentialsMetadataOnly(
      rpIdHash,
    );

    expect(credentials, hasLength(1));
    expect(credentials.single.coseAlgorithm, -7);
    expect(credentials.single.metadataOnly, isFalse);
    expect(credentials.single.publicKey, isA<ES256>());
  });
}

Map<dynamic, dynamic> _decodeRequest(List<int> command) {
  expect(command.first, Ctap2Commands.credentialManagement.value);
  return (cbor.decode(command.sublist(1)).toObject() as Map)
      .cast<dynamic, dynamic>();
}

List<int> _credentialResponse({
  required List<int> userId,
  required int coseAlgorithm,
  required bool metadataOnly,
  int? totalCredentials,
}) {
  final response = <int, dynamic>{
    6: {
      'id': CborBytes(userId),
      'name': 'user-${userId.single}',
      'displayName': 'User ${userId.single}',
    },
    7: {
      'type': 'public-key',
      'id': CborBytes([0x40 + userId.single]),
    },
    9: ?totalCredentials,
    10: 1,
  };
  if (metadataOnly) {
    response[0x80] = coseAlgorithm;
  } else {
    response[8] = {
      1: 2,
      3: coseAlgorithm,
      -1: 1,
      -2: CborBytes(List<int>.filled(32, 1)),
      -3: CborBytes(List<int>.filled(32, 2)),
    };
  }
  return cbor.encode(CborValue(response));
}

class _CredentialManagementDevice extends CtapDevice {
  final List<List<int>> responses;
  final List<List<int>> commands = [];

  _CredentialManagementDevice(this.responses);

  @override
  Future<CtapResponse<List<int>>> transceive(List<int> command) async {
    commands.add(command);
    if (command.first == Ctap2Commands.getInfo.value) {
      return CtapResponse(
        0,
        cbor.encode(
          CborValue({
            1: ['FIDO_2_1'],
            3: CborBytes(List<int>.filled(16, 0)),
            4: {'credMgmt': true},
          }),
        ),
      );
    }
    return CtapResponse(0, responses[commands.length - 2]);
  }
}
