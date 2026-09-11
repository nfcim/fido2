// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'attestation.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

Map<String, dynamic> _$AttestationResultToJson(AttestationResult instance) =>
    <String, dynamic>{
      'format': instance.format,
      'type': _$AttestationTypeEnumMap[instance.type]!,
      'aaguid': instance.aaguid,
      'trustPath': instance.trustPath,
    };

const _$AttestationTypeEnumMap = {
  AttestationType.none: 'none',
  AttestationType.self: 'self',
  AttestationType.basic: 'basic',
};
