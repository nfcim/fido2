// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'credential_mgmt.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

Map<String, dynamic> _$CredentialManagementRequestToJson(
        CredentialManagementRequest instance) =>
    <String, dynamic>{
      'subCommand': instance.subCommand,
      'params': instance.params?.toJson(),
      'pinUvAuthProtocol': instance.pinUvAuthProtocol,
      'pinUvAuthParam': instance.pinUvAuthParam,
    };

Map<String, dynamic> _$CredentialManagementResponseToJson(
        CredentialManagementResponse instance) =>
    <String, dynamic>{
      'existingResidentCredentialsCount':
          instance.existingResidentCredentialsCount,
      'maxPossibleRemainingResidentCredentialsCount':
          instance.maxPossibleRemainingResidentCredentialsCount,
      'rp': instance.rp?.toJson(),
      'rpIdHash': instance.rpIdHash,
      'totalRPs': instance.totalRPs,
      'user': instance.user?.toJson(),
      'credentialId': instance.credentialId?.toJson(),
      'publicKey': instance.publicKey?.toJson(),
      'totalCredentials': instance.totalCredentials,
      'credProtect': instance.credProtect,
      'largeBlobKey': instance.largeBlobKey,
    };
