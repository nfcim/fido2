// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'client_pin.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

Map<String, dynamic> _$ClientPinRequestToJson(ClientPinRequest instance) =>
    <String, dynamic>{
      'pinUvAuthProtocol': instance.pinUvAuthProtocol,
      'subCommand': instance.subCommand,
      'keyAgreement': instance.keyAgreement?.toJson(),
      'pinUvAuthParam': instance.pinUvAuthParam,
      'newPinEnc': instance.newPinEnc,
      'pinHashEnc': instance.pinHashEnc,
      'permissions': instance.permissions,
      'rpId': instance.rpId,
    };

Map<String, dynamic> _$ClientPinResponseToJson(ClientPinResponse instance) =>
    <String, dynamic>{
      'keyAgreement': instance.keyAgreement?.toJson(),
      'pinUvAuthToken': instance.pinUvAuthToken,
      'pinRetries': instance.pinRetries,
      'powerCycleState': instance.powerCycleState,
      'uvRetries': instance.uvRetries,
    };
