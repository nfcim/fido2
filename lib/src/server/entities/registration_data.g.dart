// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'registration_data.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

Map<String, dynamic> _$RegistrationResultToJson(RegistrationResult instance) =>
    <String, dynamic>{
      'attestation': ?instance.attestation?.toJson(),
      'credentialId': instance.credentialId,
      'credentialPublicKey': instance.credentialPublicKey.toJson(),
      'signCount': instance.signCount,
      'backupEligible': instance.backupEligible,
      'backedUp': instance.backedUp,
      'userHandle': instance.userHandle,
    };

Map<String, dynamic> _$RegisteredCredentialToJson(
  RegisteredCredential instance,
) => <String, dynamic>{
  'attestation': ?instance.attestation?.toJson(),
  'id': instance.id,
  'publicKey': instance.publicKey.toJson(),
  'signCount': instance.signCount,
  'backupEligible': instance.backupEligible,
  'backedUp': instance.backedUp,
  'userHandle': instance.userHandle,
};

Map<String, dynamic> _$RegistrationRequestToJson(
  RegistrationRequest instance,
) => <String, dynamic>{
  'publicKey': instance.publicKey,
  'challenge': instance.challenge,
  'offeredAlgorithms': instance.offeredAlgorithms,
};
