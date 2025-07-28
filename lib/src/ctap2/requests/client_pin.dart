import 'package:cbor/cbor.dart';
import 'package:fido2/src/cose.dart';
import '../constants.dart';

class ClientPinRequest {
  final int? pinUvAuthProtocol;
  final int subCommand;
  final CoseKey? keyAgreement;
  final List<int>? pinUvAuthParam;
  final List<int>? newPinEnc;
  final List<int>? pinHashEnc;
  final int? permissions;
  final String? rpId;

  ClientPinRequest({
    this.pinUvAuthProtocol,
    required this.subCommand,
    this.keyAgreement,
    this.pinUvAuthParam,
    this.newPinEnc,
    this.pinHashEnc,
    this.permissions,
    this.rpId,
  });

  List<int> encode() {
    final map = <int, dynamic>{};
    if (pinUvAuthProtocol != null) {
      map[1] = pinUvAuthProtocol!;
    }
    map[2] = subCommand;
    if (keyAgreement != null) {
      map[3] = keyAgreement!.toCbor();
    }
    if (pinUvAuthParam != null) {
      map[4] = CborBytes(pinUvAuthParam!);
    }
    if (newPinEnc != null) {
      map[5] = CborBytes(newPinEnc!);
    }
    if (pinHashEnc != null) {
      map[6] = CborBytes(pinHashEnc!);
    }
    if (permissions != null) {
      map[9] = permissions!;
    }
    if (rpId != null) {
      map[10] = CborString(rpId!);
    }
    return [Ctap2Commands.clientPIN.value] + cbor.encode(CborValue(map));
  }
}

class ClientPinResponse {
  final CoseKey? keyAgreement;
  final List<int>? pinUvAuthToken;
  final int? pinRetries;
  final bool? powerCycleState;
  final int? uvRetries;

  ClientPinResponse({
    this.keyAgreement,
    this.pinUvAuthToken,
    this.pinRetries,
    this.powerCycleState,
    this.uvRetries,
  });

  static ClientPinResponse decode(List<int> data) {
    final map = cbor.decode(data).toObject() as Map;
    final keyAgreementMap = (map[1] as Map?)?.cast<int, dynamic>();
    return ClientPinResponse(
      keyAgreement:
          keyAgreementMap != null ? CoseKey.parse(keyAgreementMap) : null,
      pinUvAuthToken: (map[2] as List?)?.cast<int>(),
      pinRetries: map[3] as int?,
      powerCycleState: map[4] as bool?,
      uvRetries: map[5] as int?,
    );
  }
}
