import 'package:cbor/cbor.dart';
import 'package:fido2/src/cose.dart';
import '../constants.dart';
import '../entities/credential_entities.dart';

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

  List<int> encode() {
    final map = <int, dynamic>{};
    map[credMgmtSubCmdIdx] = subCommand;
    if (params != null) {
      map[credMgmtParamsIdx] = params;
    }
    if (pinUvAuthProtocol != null) {
      map[credMgmtPinUvAuthProtocolIdx] = pinUvAuthProtocol!;
    }
    if (pinUvAuthParam != null) {
      map[credMgmtPinUvAuthParamIdx] = CborBytes(pinUvAuthParam!);
    }
    return [Ctap2Commands.credentialManagement.value] +
        cbor.encode(CborValue(map));
  }
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

  static CredentialManagementResponse decode(List<int> data) {
    final map = cbor.decode(data).toObject() as Map;
    final rpMap = (map[credMgmtRspRpIdx] as Map?)?.cast<String, dynamic>();
    final userMap = (map[credMgmtRspUserIdx] as Map?)?.cast<String, dynamic>();
    final credentialIdMap =
        (map[credMgmtRspCredentialIdIdx] as Map?)?.cast<String, dynamic>();
    final publicKeyMap =
        (map[credMgmtRspPublicKeyIdx] as Map?)?.cast<int, dynamic>();
    return CredentialManagementResponse(
      existingResidentCredentialsCount:
          map[credMgmtRspExistingResidentCredentialsCountIdx] as int?,
      maxPossibleRemainingResidentCredentialsCount:
          map[credMgmtRspMaxPossibleRemainingResidentCredentialsCountIdx]
              as int?,
      rp: rpMap != null ? PublicKeyCredentialRpEntity.fromCbor(rpMap) : null,
      rpIdHash: (map[credMgmtRspRpIdHashIdx] as List?)?.cast<int>(),
      totalRPs: map[credMgmtRspTotalRPsIdx] as int?,
      user: userMap != null
          ? PublicKeyCredentialUserEntity.fromCbor(userMap)
          : null,
      credentialId: credentialIdMap != null
          ? PublicKeyCredentialDescriptor.fromCbor(credentialIdMap)
          : null,
      publicKey: publicKeyMap != null ? CoseKey.parse(publicKeyMap) : null,
      totalCredentials: map[credMgmtRspTotalCredentialsIdx] as int?,
      credProtect: map[credMgmtRspCredProtectIdx] as int?,
      largeBlobKey: (map[credMgmtRspLargeBlobKeyIdx] as List?)?.cast<int>(),
    );
  }
}
