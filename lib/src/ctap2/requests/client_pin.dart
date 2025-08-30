import 'package:cbor/cbor.dart';
import 'package:fido2/src/cose.dart';
import '../constants.dart';
import 'package:fido2/src/utils/serialization.dart';
import 'package:json_annotation/json_annotation.dart';

part 'client_pin.g.dart';

@JsonSerializable(createFactory: false, explicitToJson: true)
class ClientPinRequest with JsonToStringMixin {
  static const int pinUvAuthProtocolIdx = 1;
  static const int subCommandIdx = 2;
  static const int keyAgreementIdx = 3;
  static const int pinUvAuthParamIdx = 4;
  static const int newPinEncIdx = 5;
  static const int pinHashEncIdx = 6;
  static const int permissionsIdx = 9;
  static const int rpIdIdx = 10;

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
      map[pinUvAuthProtocolIdx] = pinUvAuthProtocol!;
    }
    map[subCommandIdx] = subCommand;
    if (keyAgreement != null) {
      map[keyAgreementIdx] = keyAgreement!.toCbor();
    }
    if (pinUvAuthParam != null) {
      map[pinUvAuthParamIdx] = CborBytes(pinUvAuthParam!);
    }
    if (newPinEnc != null) {
      map[newPinEncIdx] = CborBytes(newPinEnc!);
    }
    if (pinHashEnc != null) {
      map[pinHashEncIdx] = CborBytes(pinHashEnc!);
    }
    if (permissions != null) {
      map[permissionsIdx] = permissions!;
    }
    if (rpId != null) {
      map[rpIdIdx] = CborString(rpId!);
    }
    return [Ctap2Commands.clientPIN.value] + cbor.encode(CborValue(map));
  }

  @override
  Map<String, dynamic> toJson() => _$ClientPinRequestToJson(this);
}

@JsonSerializable(createFactory: false, explicitToJson: true)
class ClientPinResponse with JsonToStringMixin {
  static const int keyAgreementIdx = 1;
  static const int pinUvAuthTokenIdx = 2;
  static const int pinRetriesIdx = 3;
  static const int powerCycleStateIdx = 4;
  static const int uvRetriesIdx = 5;

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
    final keyAgreementMap =
        (map[keyAgreementIdx] as Map?)?.cast<int, dynamic>();
    return ClientPinResponse(
      keyAgreement:
          keyAgreementMap != null ? CoseKey.parse(keyAgreementMap) : null,
      pinUvAuthToken: (map[pinUvAuthTokenIdx] as List?)?.cast<int>(),
      pinRetries: map[pinRetriesIdx] as int?,
      powerCycleState: map[powerCycleStateIdx] as bool?,
      uvRetries: map[uvRetriesIdx] as int?,
    );
  }

  @override
  Map<String, dynamic> toJson() => _$ClientPinResponseToJson(this);
}
