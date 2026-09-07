import 'package:cbor/cbor.dart';
import 'package:convert/convert.dart';
import 'package:fido2/src/cose.dart';
import 'package:fido2/src/ctap.dart';
import '../strict_cbor.dart';

T? _field<T extends CborValue>(CborMap map, Object label,
    {bool required = false}) {
  final value = map[CborValue(label)];
  if (value == null && !required) return null;
  if (value is! T || value.tags.isNotEmpty) {
    throw FormatException('Invalid CTAP field $label: expected $T');
  }
  return value;
}

CborMap _responseMap(List<int> data) {
  final value = decodeStrictCbor(data);
  if (value is! CborMap || value.tags.isNotEmpty) {
    throw const FormatException('Expected untagged CTAP response map');
  }
  return value;
}

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

class PublicKeyCredentialRpEntity {
  final String id;

  PublicKeyCredentialRpEntity({required this.id});

  @override
  String toString() {
    return 'PublicKeyCredentialRpEntity(id: $id)';
  }
}

class PublicKeyCredentialUserEntity {
  final List<int> id;
  final String name;
  final String displayName;

  PublicKeyCredentialUserEntity({
    required this.id,
    required this.name,
    required this.displayName,
  });

  CborValue toCbor() {
    return CborValue({
      'id': CborBytes(id),
      'name': name,
      'displayName': displayName,
    });
  }

  @override
  String toString() {
    return 'PublicKeyCredentialUserEntity(id: ${hex.encode(id)}, name: $name, displayName: $displayName)';
  }
}

class PublicKeyCredentialDescriptor {
  final String type;
  final List<int> id;

  PublicKeyCredentialDescriptor({
    required this.type,
    required this.id,
  });

  CborValue toCbor() {
    return CborValue({
      'type': type,
      'id': CborBytes(id),
    });
  }

  @override
  String toString() {
    return 'PublicKeyCredentialDescriptor(type: $type, id: ${hex.encode(id)})';
  }
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
  final List<Map<String, dynamic>>? algorithms;
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

class CredentialManagementRequest {
  final int subCommand;
  final CborMap? params;
  final int? pinUvAuthProtocol;
  final List<int>? pinUvAuthParam;

  CredentialManagementRequest({
    required this.subCommand,
    this.params,
    this.pinUvAuthProtocol,
    this.pinUvAuthParam,
  });
}

class CredentialManagementResponse {
  final int? existingResidentCredentialsCount;
  final int? maxPossibleRemainingResidentCredentialsCount;
  final PublicKeyCredentialRpEntity? rp;
  final List<int>? rpIdHash;
  final int? totalRPs;
  final PublicKeyCredentialUserEntity? user;
  final PublicKeyCredentialDescriptor? credentialId;
  final CoseKey? publicKey;
  final int? totalCredentials;
  final int? credProtect;
  final List<int>? largeBlobKey;

  CredentialManagementResponse({
    this.existingResidentCredentialsCount,
    this.maxPossibleRemainingResidentCredentialsCount,
    this.rp,
    this.rpIdHash,
    this.totalRPs,
    this.user,
    this.credentialId,
    this.publicKey,
    this.totalCredentials,
    this.credProtect,
    this.largeBlobKey,
  });
}

class Ctap2 {
  late final AuthenticatorInfo _info;
  final CtapDevice device;
  final CoseConfiguration? coseConfiguration;

  Ctap2._create(this.device, this.coseConfiguration);

  static Future<Ctap2> create(CtapDevice device,
      {CoseConfiguration? coseConfiguration}) async {
    final ctap2 = Ctap2._create(device, coseConfiguration);
    final res = await ctap2.refreshInfo();
    if (res.status != 0) {
      throw Exception('GetInfo failed.');
    }
    ctap2._info = res.data;
    return ctap2;
  }

  AuthenticatorInfo get info => _info;

  Future<CtapResponse<AuthenticatorInfo>> refreshInfo() async {
    final req = makeGetInfoRequest();
    final res = await device.transceive(req);
    return CtapResponse(res.status, parseGetInfoResponse(res.data));
  }

  Future<CtapResponse<ClientPinResponse?>> clientPin(
      ClientPinRequest request) async {
    final req = makeClientPinRequest(request);
    final res = await device.transceive(req);
    return CtapResponse(
        res.status, res.data.isEmpty ? null : parseClientPinResponse(res.data));
  }

  Future<CtapResponse<CredentialManagementResponse?>> credentialManagement(
      CredentialManagementRequest request) async {
    final req = makeCredentialManagementRequest(request);
    final res = await device.transceive(req);
    return CtapResponse(
        res.status,
        res.data.isEmpty
            ? null
            : parseCredentialManagementResponse(res.data,
                configuration: coseConfiguration));
  }

  Future<CtapResponse> reset() async {
    final req = [Ctap2Commands.reset.value];
    final res = await device.transceive(req);
    return CtapResponse(res.status, null);
  }

  /// Make the request to get info from the authenticator.
  static List<int> makeGetInfoRequest() {
    return [Ctap2Commands.getInfo.value];
  }

  /// Parse the response from the authenticator.
  static AuthenticatorInfo parseGetInfoResponse(List<int> data) {
    final map = _responseMap(data).toObject() as Map;
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
      algorithms: (map[10] as List?)
          ?.map((entry) => Map<String, dynamic>.from(entry as Map))
          .toList(),
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
    final encoded = _responseMap(data);
    final keyAgreementMap = _field<CborMap>(encoded, 1);
    return ClientPinResponse(
      keyAgreement:
          keyAgreementMap != null ? CoseKey.fromCborMap(keyAgreementMap) : null,
      pinUvAuthToken: _field<CborBytes>(encoded, 2)?.bytes,
      pinRetries: _field<CborInt>(encoded, 3)?.toInt(),
      powerCycleState: _field<CborBool>(encoded, 4)?.toObject() as bool?,
      uvRetries: _field<CborInt>(encoded, 5)?.toInt(),
    );
  }

  /// Make the request to credentialManagement.
  static List<int> makeCredentialManagementRequest(
      CredentialManagementRequest request) {
    final map = <int, dynamic>{};
    map[1] = request.subCommand;
    if (request.params != null) {
      map[2] = request.params;
    }
    if (request.pinUvAuthProtocol != null) {
      map[3] = request.pinUvAuthProtocol!;
    }
    if (request.pinUvAuthParam != null) {
      map[4] = CborBytes(request.pinUvAuthParam!);
    }
    return [Ctap2Commands.credentialManagement.value] +
        cbor.encode(CborValue(map));
  }

  /// Parse the response from credentialManagement.
  static CredentialManagementResponse parseCredentialManagementResponse(
      List<int> data,
      {CoseConfiguration? configuration}) {
    final encoded = _responseMap(data);
    final rpMap = _field<CborMap>(encoded, 3);
    final userMap = _field<CborMap>(encoded, 6);
    final credentialIdMap = _field<CborMap>(encoded, 7);
    final publicKeyMap = _field<CborMap>(encoded, 8);
    return CredentialManagementResponse(
      existingResidentCredentialsCount: _field<CborInt>(encoded, 1)?.toInt(),
      maxPossibleRemainingResidentCredentialsCount:
          _field<CborInt>(encoded, 2)?.toInt(),
      rp: rpMap != null
          ? PublicKeyCredentialRpEntity(
              id: _field<CborString>(rpMap, 'id', required: true)!.toString())
          : null,
      rpIdHash: _field<CborBytes>(encoded, 4)?.bytes,
      totalRPs: _field<CborInt>(encoded, 5)?.toInt(),
      user: userMap != null
          ? PublicKeyCredentialUserEntity(
              id: _field<CborBytes>(userMap, 'id', required: true)!.bytes,
              name: _field<CborString>(userMap, 'name', required: true)!
                  .toString(),
              displayName:
                  _field<CborString>(userMap, 'displayName', required: true)!
                      .toString(),
            )
          : null,
      credentialId: credentialIdMap != null
          ? PublicKeyCredentialDescriptor(
              type: _field<CborString>(credentialIdMap, 'type', required: true)!
                  .toString(),
              id: _field<CborBytes>(credentialIdMap, 'id', required: true)!
                  .bytes,
            )
          : null,
      publicKey: publicKeyMap != null
          ? CoseKey.fromCborMap(publicKeyMap, configuration: configuration)
          : null,
      totalCredentials: _field<CborInt>(encoded, 9)?.toInt(),
      credProtect: _field<CborInt>(encoded, 10)?.toInt(),
      largeBlobKey: _field<CborBytes>(encoded, 11)?.bytes,
    );
  }
}
