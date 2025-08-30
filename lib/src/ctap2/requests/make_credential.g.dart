// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'make_credential.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

Map<String, dynamic> _$MakeCredentialRequestToJson(
        MakeCredentialRequest instance) =>
    <String, dynamic>{
      'clientDataHash': instance.clientDataHash,
      'rp': instance.rp.toJson(),
      'user': instance.user.toJson(),
      'pubKeyCredParams': instance.pubKeyCredParams,
      'excludeList': instance.excludeList?.map((e) => e.toJson()).toList(),
      'extensions': instance.extensions,
      'options': instance.options,
      'pinAuth': instance.pinAuth,
      'pinProtocol': instance.pinProtocol,
      'enterpriseAttestation': instance.enterpriseAttestation,
    };

Map<String, dynamic> _$MakeCredentialResponseToJson(
        MakeCredentialResponse instance) =>
    <String, dynamic>{
      'fmt': instance.fmt,
      'authData': instance.authData,
      'attStmt': instance.attStmt,
      'epAtt': instance.epAtt,
      'largeBlobKey': instance.largeBlobKey,
    };
