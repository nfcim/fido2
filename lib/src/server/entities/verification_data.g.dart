// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'verification_data.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

Map<String, dynamic> _$VerificationResultToJson(VerificationResult instance) =>
    <String, dynamic>{
      'userPresent': instance.userPresent,
      'userVerified': instance.userVerified,
      'signCount': instance.signCount,
      'authenticatorData': instance.authenticatorData,
      'backupEligible': instance.backupEligible,
      'backedUp': instance.backedUp,
    };

Map<String, dynamic> _$AuthenticationResultToJson(
  AuthenticationResult instance,
) => <String, dynamic>{
  'signCount': instance.signCount,
  'backedUp': instance.backedUp,
};
