import 'package:cbor/cbor.dart';
import 'package:convert/convert.dart';
import 'package:fido2/src/cose.dart';
import '../constants.dart';
import '../entities/credential_entities.dart';

class CredentialManagementRequest {
  static const int subCmdIdx = 1;
  static const int paramsIdx = 2;
  static const int pinUvAuthProtocolIdx = 3;
  static const int pinUvAuthParamIdx = 4;

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
    map[subCmdIdx] = subCommand;
    if (params != null) {
      map[paramsIdx] = params;
    }
    if (pinUvAuthProtocol != null) {
      map[pinUvAuthProtocolIdx] = pinUvAuthProtocol!;
    }
    if (pinUvAuthParam != null) {
      map[pinUvAuthParamIdx] = CborBytes(pinUvAuthParam!);
    }
    return [Ctap2Commands.credentialManagement.value] +
        cbor.encode(CborValue(map));
  }

  @override
  String toString() {
    final buffer = StringBuffer();
    buffer.writeln('CredentialManagementRequest(');
    buffer.writeln('  subCommand: $subCommand,');

    if (params != null) {
      buffer.writeln('  params: $params,');
    }
    if (pinUvAuthProtocol != null) {
      buffer.writeln('  pinUvAuthProtocol: $pinUvAuthProtocol,');
    }
    if (pinUvAuthParam != null) {
      buffer.writeln('  pinUvAuthParam: ${hex.encode(pinUvAuthParam!)},');
    }

    buffer.write(')');
    return buffer.toString();
  }
}

class CredentialManagementResponse {
  static const int existingResidentCredentialsCountIdx = 1;
  static const int maxPossibleRemainingResidentCredentialsCountIdx = 2;
  static const int rpIdx = 3;
  static const int rpIdHashIdx = 4;
  static const int totalRPsIdx = 5;
  static const int userIdx = 6;
  static const int credentialIdIdx = 7;
  static const int publicKeyIdx = 8;
  static const int totalCredentialsIdx = 9;
  static const int credProtectIdx = 10;
  static const int largeBlobKeyIdx = 11;

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
    final rpMap = (map[rpIdx] as Map?)?.cast<String, dynamic>();
    final userMap = (map[userIdx] as Map?)?.cast<String, dynamic>();
    final credentialIdMap =
        (map[credentialIdIdx] as Map?)?.cast<String, dynamic>();
    final publicKeyMap = (map[publicKeyIdx] as Map?)?.cast<int, dynamic>();
    return CredentialManagementResponse(
      existingResidentCredentialsCount:
          map[existingResidentCredentialsCountIdx] as int?,
      maxPossibleRemainingResidentCredentialsCount:
          map[maxPossibleRemainingResidentCredentialsCountIdx] as int?,
      rp: rpMap != null ? PublicKeyCredentialRpEntity.fromCbor(rpMap) : null,
      rpIdHash: (map[rpIdHashIdx] as List?)?.cast<int>(),
      totalRPs: map[totalRPsIdx] as int?,
      user: userMap != null
          ? PublicKeyCredentialUserEntity.fromCbor(userMap)
          : null,
      credentialId: credentialIdMap != null
          ? PublicKeyCredentialDescriptor.fromCbor(credentialIdMap)
          : null,
      publicKey: publicKeyMap != null ? CoseKey.parse(publicKeyMap) : null,
      totalCredentials: map[totalCredentialsIdx] as int?,
      credProtect: map[credProtectIdx] as int?,
      largeBlobKey: (map[largeBlobKeyIdx] as List?)?.cast<int>(),
    );
  }

  @override
  String toString() {
    final buffer = StringBuffer();
    buffer.writeln('CredentialManagementResponse(');

    if (existingResidentCredentialsCount != null) {
      buffer.writeln(
          '  existingResidentCredentialsCount: $existingResidentCredentialsCount,');
    }
    if (maxPossibleRemainingResidentCredentialsCount != null) {
      buffer.writeln(
          '  maxPossibleRemainingResidentCredentialsCount: $maxPossibleRemainingResidentCredentialsCount,');
    }
    if (rp != null) {
      buffer.writeln('  rp: $rp,');
    }
    if (rpIdHash != null) {
      buffer.writeln('  rpIdHash: ${hex.encode(rpIdHash!)},');
    }
    if (totalRPs != null) {
      buffer.writeln('  totalRPs: $totalRPs,');
    }
    if (user != null) {
      buffer.writeln('  user: $user,');
    }
    if (credentialId != null) {
      buffer.writeln('  credentialId: $credentialId,');
    }
    if (publicKey != null) {
      buffer.writeln('  publicKey: $publicKey,');
    }
    if (totalCredentials != null) {
      buffer.writeln('  totalCredentials: $totalCredentials,');
    }
    if (credProtect != null) {
      buffer.writeln('  credProtect: $credProtect,');
    }
    if (largeBlobKey != null) {
      buffer.writeln('  largeBlobKey: ${hex.encode(largeBlobKey!)},');
    }

    buffer.write(')');
    return buffer.toString();
  }
}
