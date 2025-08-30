// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'credmgmt.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

Map<String, dynamic> _$CmMetadataToJson(CmMetadata instance) =>
    <String, dynamic>{
      'existingResidentCredentialsCount':
          instance.existingResidentCredentialsCount,
      'maxPossibleRemainingResidentCredentialsCount':
          instance.maxPossibleRemainingResidentCredentialsCount,
    };

Map<String, dynamic> _$CmRpToJson(CmRp instance) => <String, dynamic>{
      'rp': instance.rp.toJson(),
      'rpIdHash': instance.rpIdHash,
      'totalRPs': instance.totalRPs,
    };

Map<String, dynamic> _$CmCredentialToJson(CmCredential instance) =>
    <String, dynamic>{
      'user': instance.user.toJson(),
      'credentialId': instance.credentialId.toJson(),
      'publicKey': instance.publicKey.toJson(),
      'totalCredentials': instance.totalCredentials,
      'credProtect': instance.credProtect,
      'largeBlobKey': instance.largeBlobKey,
    };
