// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'ctap.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

Map<String, dynamic> _$CtapResponseToJson<T>(
  CtapResponse<T> instance,
  Object? Function(T value) toJsonT,
) =>
    <String, dynamic>{
      'status': instance.status,
      'data': toJsonT(instance.data),
    };
