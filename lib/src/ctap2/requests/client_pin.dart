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
}

class ClientPinUtils {
  /// Make the request to clientPin.
  static List<int> makeClientPinRequest(ClientPinRequest request) {
    final map = <int, dynamic>{};
    if (request.pinUvAuthProtocol != null) {
      map[1] = request.pinUvAuthProtocol!;
    }
    map[2] = request.subCommand;
    if (request.keyAgreement != null) {
      map[3] = request.keyAgreement!.toCbor();
    }
    if (request.pinUvAuthParam != null) {
      map[4] = CborBytes(request.pinUvAuthParam!);
    }
    if (request.newPinEnc != null) {
      map[5] = CborBytes(request.newPinEnc!);
    }
    if (request.pinHashEnc != null) {
      map[6] = CborBytes(request.pinHashEnc!);
    }
    if (request.permissions != null) {
      map[9] = request.permissions!;
    }
    if (request.rpId != null) {
      map[10] = CborString(request.rpId!);
    }
    return [Ctap2Commands.clientPIN.value] + cbor.encode(CborValue(map));
  }

  /// Parse the response from clientPin.
  static ClientPinResponse parseClientPinResponse(List<int> data) {
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