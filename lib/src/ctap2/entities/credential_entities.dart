import 'package:cbor/cbor.dart';
import 'package:json_annotation/json_annotation.dart';
import 'package:fido2/src/utils/serialization.dart';

part 'credential_entities.g.dart';

@JsonSerializable(createFactory: false)
class PublicKeyCredentialRpEntity with JsonToStringMixin {
  final String id;

  PublicKeyCredentialRpEntity({required this.id});

  factory PublicKeyCredentialRpEntity.fromCbor(Map<dynamic, dynamic> cbor) {
    return PublicKeyCredentialRpEntity(
      id: cbor['id'] as String,
    );
  }

  CborValue toCbor() {
    return CborValue({
      'id': id,
    });
  }

  @override
  Map<String, dynamic> toJson() => _$PublicKeyCredentialRpEntityToJson(this);
}

@JsonSerializable(createFactory: false)
class PublicKeyCredentialUserEntity with JsonToStringMixin {
  final List<int> id;
  final String name;
  final String displayName;

  PublicKeyCredentialUserEntity({
    required this.id,
    required this.name,
    required this.displayName,
  });

  factory PublicKeyCredentialUserEntity.fromCbor(Map<dynamic, dynamic> cbor) {
    return PublicKeyCredentialUserEntity(
      id: (cbor['id'] as List).cast<int>(),
      name: cbor['name'] as String,
      displayName: cbor['displayName'] as String,
    );
  }

  CborValue toCbor() {
    return CborValue({
      'id': CborBytes(id),
      'name': name,
      'displayName': displayName,
    });
  }

  @override
  Map<String, dynamic> toJson() => _$PublicKeyCredentialUserEntityToJson(this);
}

@JsonSerializable(createFactory: false)
class PublicKeyCredentialDescriptor with JsonToStringMixin {
  final String type;
  final List<int> id;
  final List<String>? transports;

  PublicKeyCredentialDescriptor(
      {required this.type, required this.id, this.transports});

  factory PublicKeyCredentialDescriptor.fromCbor(Map<dynamic, dynamic> cbor) {
    return PublicKeyCredentialDescriptor(
      type: cbor['type'] as String,
      id: (cbor['id'] as List).cast<int>(),
      transports: (cbor['transports'] as List?)?.cast<String>(),
    );
  }

  CborValue toCbor() {
    final map = <String, dynamic>{
      'type': type,
      'id': CborBytes(id),
    };
    if (transports != null) {
      map['transports'] = transports;
    }
    return CborValue(map);
  }

  @override
  Map<String, dynamic> toJson() => _$PublicKeyCredentialDescriptorToJson(this);
}
