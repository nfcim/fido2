import 'package:cbor/cbor.dart';
import 'package:convert/convert.dart';

class PublicKeyCredentialRpEntity {
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
  String toString() {
    final buffer = StringBuffer();
    buffer.writeln('PublicKeyCredentialRpEntity(');
    buffer.writeln('  id: $id');
    buffer.write(')');
    return buffer.toString();
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
  String toString() {
    final buffer = StringBuffer();
    buffer.writeln('PublicKeyCredentialUserEntity(');
    buffer.writeln('  id: ${hex.encode(id)},');
    buffer.writeln('  name: $name,');
    buffer.writeln('  displayName: $displayName');
    buffer.write(')');
    return buffer.toString();
  }
}

class PublicKeyCredentialDescriptor {
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
  String toString() {
    final buffer = StringBuffer();
    buffer.writeln('PublicKeyCredentialDescriptor(');
    buffer.writeln('  type: $type,');
    buffer.writeln('  id: ${hex.encode(id)},');
    if (transports != null) buffer.writeln('  transports: $transports,');
    buffer.write(')');
    return buffer.toString();
  }
}
