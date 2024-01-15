import 'package:cbor/cbor.dart' as cb;
import 'package:cbor/simple.dart';

import 'package:fido2/src/cose.dart';

enum Ctap2Commands {
  makeCredential(0x01),
  getAssertion(0x02),
  getInfo(0x04),
  clientPIN(0x06),
  reset(0x07),
  getNextAssertion(0x08),
  credentialManagement(0x0A),
  selection(0x0B),
  largeBlobs(0x0C),
  config(0x0D);

  const Ctap2Commands(this.value);

  final int value;
}

class AuthenticatorInfo {
  final List<String> versions;
  final List<String>? extensions;
  final List<int> aaguid;
  final Map<String, bool>? options;
  final int? maxMsgSize;
  final List<int>? pinUvAuthProtocols;
  final int? maxCredentialCountInList;
  final int? maxCredentialIdLength;
  final List<String>? transports;
  final List<Map<String, int>>? algorithms;
  final int? maxSerializedLargeBlobArray;
  final bool? forcePinChange;
  final int? minPinLength;
  final int? firmwareVersion;
  final int? maxCredBlobLength;
  final int? maxRpIdsForSetMinPinLength;
  final int? preferredPlatformUvAttempts;
  final int? uvModality;
  final Map<String, int>? certifications;
  final int? remainingDiscoverableCredentials;
  final List<int>? vendorPrototypeConfigCommands;

  AuthenticatorInfo({
    required this.versions,
    this.extensions,
    required this.aaguid,
    this.options,
    this.maxMsgSize,
    this.pinUvAuthProtocols,
    this.maxCredentialCountInList,
    this.maxCredentialIdLength,
    this.transports,
    this.algorithms,
    this.maxSerializedLargeBlobArray,
    this.forcePinChange,
    this.minPinLength,
    this.firmwareVersion,
    this.maxCredBlobLength,
    this.maxRpIdsForSetMinPinLength,
    this.preferredPlatformUvAttempts,
    this.uvModality,
    this.certifications,
    this.remainingDiscoverableCredentials,
    this.vendorPrototypeConfigCommands,
  });
}

enum ClientPinSubCommand {
  getPinRetries(0x01),
  getKeyAgreement(0x02),
  setPin(0x03),
  changePin(0x04),
  getPinToken(0x05),
  getPinUvAuthTokenUsingUvWithPermissions(0x06),
  getUvRetries(0x07),
  getPinUvAuthTokenUsingPinWithPermissions(0x08);

  const ClientPinSubCommand(this.value);

  final int value;
}

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

class Ctap2 {
  /// Make the request to get info from the authenticator.
  static List<int> makeGetInfoRequest() {
    return [Ctap2Commands.getInfo.value];
  }

  /// Parse the response from the authenticator.
  static AuthenticatorInfo parseGetInfoResponse(List<int> data) {
    var map = cbor.decode(data) as Map;
    return AuthenticatorInfo(
      versions: (map[1] as List).cast<String>(),
      extensions: (map[2] as List?)?.cast<String>(),
      aaguid: map[3] as List<int>,
      options: (map[4] as Map?)?.cast<String, bool>(),
      maxMsgSize: map[5] as int?,
      pinUvAuthProtocols: (map[6] as List?)?.cast<int>(),
      maxCredentialCountInList: map[7] as int?,
      maxCredentialIdLength: map[8] as int?,
      transports: (map[9] as List?)?.cast<String>(),
      algorithms: (map[10] as List?)?.cast<Map<String, int>>(),
      maxSerializedLargeBlobArray: map[11] as int?,
      forcePinChange: map[12] as bool?,
      minPinLength: map[13] as int?,
      firmwareVersion: map[14] as int?,
      maxCredBlobLength: map[15] as int?,
      maxRpIdsForSetMinPinLength: map[16] as int?,
      preferredPlatformUvAttempts: map[17] as int?,
      uvModality: map[18] as int?,
      certifications: (map[19] as Map?)?.cast<String, int>(),
      remainingDiscoverableCredentials: map[20] as int?,
      vendorPrototypeConfigCommands: (map[21] as List?)?.cast<int>(),
    );
  }

  static List<int> makeClientPinRequest(ClientPinRequest request) {
    var map = <int, dynamic>{};
    if (request.pinUvAuthProtocol != null) {
      map[1] = request.pinUvAuthProtocol;
    }
    map[2] = request.subCommand;
    if (request.keyAgreement != null) {
      map[3] = request.keyAgreement!.toCbor();
    }
    if (request.pinUvAuthParam != null) {
      map[4] = cb.CborBytes(request.pinUvAuthParam!);
    }
    if (request.newPinEnc != null) {
      map[5] = cb.CborBytes(request.newPinEnc!);
    }
    if (request.pinHashEnc != null) {
      map[6] = cb.CborBytes(request.pinHashEnc!);
    }
    if (request.permissions != null) {
      map[9] = request.permissions;
    }
    if (request.rpId != null) {
      map[10] = request.rpId;
    }
    return [Ctap2Commands.clientPIN.value] + cbor.encode(map);
  }

  static ClientPinResponse parseClientPinResponse(List<int> data) {
    var map = cbor.decode(data) as Map;
    var keyAgreementMap = (map[1] as Map?)?.cast<int, dynamic>();
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
