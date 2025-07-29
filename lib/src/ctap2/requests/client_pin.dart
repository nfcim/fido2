import 'package:cbor/cbor.dart';
import 'package:convert/convert.dart';
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
      map[cpPinUvAuthProtocolIdx] = pinUvAuthProtocol!;
    }
    map[cpSubCommandIdx] = subCommand;
    if (keyAgreement != null) {
      map[cpKeyAgreementIdx] = keyAgreement!.toCbor();
    }
    if (pinUvAuthParam != null) {
      map[cpPinUvAuthParamIdx] = CborBytes(pinUvAuthParam!);
    }
    if (newPinEnc != null) {
      map[cpNewPinEncIdx] = CborBytes(newPinEnc!);
    }
    if (pinHashEnc != null) {
      map[cpPinHashEncIdx] = CborBytes(pinHashEnc!);
    }
    if (permissions != null) {
      map[cpPermissionsIdx] = permissions!;
    }
    if (rpId != null) {
      map[cpRpIdIdx] = CborString(rpId!);
    }
    return [Ctap2Commands.clientPIN.value] + cbor.encode(CborValue(map));
  }

  @override
  String toString() {
    final buffer = StringBuffer();
    buffer.writeln('ClientPinRequest(');
    buffer.writeln('  subCommand: $subCommand,');

    if (pinUvAuthProtocol != null) {
      buffer.writeln('  pinUvAuthProtocol: $pinUvAuthProtocol,');
    }
    if (keyAgreement != null) {
      buffer.writeln('  keyAgreement: $keyAgreement,');
    }
    if (pinUvAuthParam != null) {
      buffer.writeln('  pinUvAuthParam: ${hex.encode(pinUvAuthParam!)},');
    }
    if (newPinEnc != null) {
      buffer.writeln('  newPinEnc: ${hex.encode(newPinEnc!)},');
    }
    if (pinHashEnc != null) {
      buffer.writeln('  pinHashEnc: ${hex.encode(pinHashEnc!)},');
    }
    if (permissions != null) {
      buffer.writeln('  permissions: $permissions,');
    }
    if (rpId != null) {
      buffer.writeln('  rpId: $rpId,');
    }

    buffer.write(')');
    return buffer.toString();
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
    final keyAgreementMap =
        (map[cpRspKeyAgreementIdx] as Map?)?.cast<int, dynamic>();
    return ClientPinResponse(
      keyAgreement:
          keyAgreementMap != null ? CoseKey.parse(keyAgreementMap) : null,
      pinUvAuthToken: (map[cpRspPinUvAuthTokenIdx] as List?)?.cast<int>(),
      pinRetries: map[cpRspPinRetriesIdx] as int?,
      powerCycleState: map[cpRspPowerCycleStateIdx] as bool?,
      uvRetries: map[cpRspUvRetriesIdx] as int?,
    );
  }

  @override
  String toString() {
    final buffer = StringBuffer();
    buffer.writeln('ClientPinResponse(');

    if (keyAgreement != null) buffer.writeln('  keyAgreement: $keyAgreement,');
    if (pinUvAuthToken != null) {
      buffer.writeln('  pinUvAuthToken: ${hex.encode(pinUvAuthToken!)},');
    }
    if (pinRetries != null) buffer.writeln('  pinRetries: $pinRetries,');
    if (powerCycleState != null) {
      buffer.writeln('  powerCycleState: $powerCycleState,');
    }
    if (uvRetries != null) buffer.writeln('  uvRetries: $uvRetries,');

    buffer.write(')');
    return buffer.toString();
  }
}
