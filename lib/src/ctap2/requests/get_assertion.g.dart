// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'get_assertion.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

Map<String, dynamic> _$GetAssertionRequestToJson(
        GetAssertionRequest instance) =>
    <String, dynamic>{
      'rpId': instance.rpId,
      'clientDataHash': instance.clientDataHash,
      'allowList': instance.allowList?.map((e) => e.toJson()).toList(),
      'extensions': instance.extensions,
      'options': instance.options,
      'pinAuth': instance.pinAuth,
      'pinProtocol': instance.pinProtocol,
    };

Map<String, dynamic> _$GetAssertionResponseToJson(
        GetAssertionResponse instance) =>
    <String, dynamic>{
      'credential': instance.credential.toJson(),
      'authData': instance.authData,
      'signature': instance.signature,
      'user': instance.user?.toJson(),
      'numberOfCredentials': instance.numberOfCredentials,
      'userSelected': instance.userSelected,
      'largeBlobKey': instance.largeBlobKey,
    };
