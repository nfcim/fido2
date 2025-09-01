// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'authenticator_data.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

Map<String, dynamic> _$AttestedCredentialDataToJson(
        AttestedCredentialData instance) =>
    <String, dynamic>{
      'aaguid': instance.aaguid,
      'credentialId': instance.credentialId,
      'credentialPublicKey': instance.credentialPublicKey.toJson(),
    };

Map<String, dynamic> _$AuthenticatorDataToJson(AuthenticatorData instance) =>
    <String, dynamic>{
      'rpIdHash': instance.rpIdHash,
      'flags': instance.flags,
      'signCount': instance.signCount,
      'attestedCredentialData': instance.attestedCredentialData?.toJson(),
      'extensions': instance.extensions?.toJson(),
      'userPresent': instance.userPresent,
      'userVerified': instance.userVerified,
      'hasAttestedCredentialData': instance.hasAttestedCredentialData,
      'hasExtensions': instance.hasExtensions,
    };
