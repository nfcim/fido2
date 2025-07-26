import 'package:cbor/cbor.dart';
import 'package:convert/convert.dart';

class PublicKeyCredentialRpEntity {
  final String id;

  PublicKeyCredentialRpEntity({required this.id});

  CborValue toCbor() {
    return CborValue({
      'id': id,
    });
  }

  @override
  String toString() {
    return 'PublicKeyCredentialRpEntity(id: $id)';
  }
}

class PublicKeyCredentialUserEntity {
  final List<int> id;
  final String name;
  final String displayName;

  PublicKeyCredentialUserEntity({
    required this.id,
    required this.name,
    required this.displayName,
  });

  CborValue toCbor() {
    return CborValue({
      'id': CborBytes(id),
      'name': name,
      'displayName': displayName,
    });
  }

  @override
  String toString() {
    return 'PublicKeyCredentialUserEntity(id: ${hex.encode(id)}, name: $name, displayName: $displayName)';
  }
}

class PublicKeyCredentialDescriptor {
  final String type;
  final List<int> id;

  PublicKeyCredentialDescriptor({
    required this.type,
    required this.id,
  });

  CborValue toCbor() {
    return CborValue({
      'type': type,
      'id': CborBytes(id),
    });
  }

  @override
  String toString() {
    return 'PublicKeyCredentialDescriptor(type: $type, id: ${hex.encode(id)})';
  }
}
