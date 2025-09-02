import 'package:cbor/cbor.dart';
import 'package:json_annotation/json_annotation.dart';
import 'package:fido2/src/utils/serialization.dart';

part 'credential_entities.g.dart';

/// WebAuthn Relying Party (RP) parameters used during credential creation
/// (see spec §5.4.2). Contains the RP identifier.
@JsonSerializable(createFactory: false)
class PublicKeyCredentialRpEntity with JsonToStringMixin {
  /// A unique identifier for the Relying Party entity; sets the RP ID.
  final String id;

  PublicKeyCredentialRpEntity({required this.id});

  /// Parses from a CBOR map as used in CTAP requests.
  factory PublicKeyCredentialRpEntity.fromCbor(Map<dynamic, dynamic> cbor) {
    return PublicKeyCredentialRpEntity(
      id: cbor['id'] as String,
    );
  }

  /// Serializes this RP entity to a CBOR map for CTAP.
  CborValue toCbor() {
    return CborValue({
      'id': id,
    });
  }

  @override
  Map<String, dynamic> toJson() => _$PublicKeyCredentialRpEntityToJson(this);
}

/// WebAuthn user account parameters for credential creation (spec §5.4.3).
/// Includes an opaque user handle and human-readable names.
@JsonSerializable(createFactory: false)
class PublicKeyCredentialUserEntity with JsonToStringMixin {
  /// Opaque user handle (max 64 bytes). Used for auth decisions.
  final List<int> id;

  /// Machine-readable account name (not for auth decisions).
  final String name;

  /// Human-palatable display name. May be empty.
  final String displayName;

  PublicKeyCredentialUserEntity({
    required this.id,
    required this.name,
    required this.displayName,
  });

  /// Parses from a CBOR map as used in CTAP requests.
  factory PublicKeyCredentialUserEntity.fromCbor(Map<dynamic, dynamic> cbor) {
    return PublicKeyCredentialUserEntity(
      id: (cbor['id'] as List).cast<int>(),
      name: cbor['name'] as String,
      displayName: cbor['displayName'] as String,
    );
  }

  /// Serializes this user entity to a CBOR map for CTAP.
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

/// Identifies a specific credential (spec §5.8.3). Used to hint which
/// credentials to create or allow during operations.
@JsonSerializable(createFactory: false)
class PublicKeyCredentialDescriptor with JsonToStringMixin {
  /// Type of the public key credential (e.g. "public-key"). Unknown types
  /// are ignored by platforms.
  final String type;

  /// Credential ID of the public key credential being referenced.
  final List<int> id;

  /// Optional hint of how to reach the authenticator (transports).
  final List<String>? transports;

  PublicKeyCredentialDescriptor(
      {required this.type, required this.id, this.transports});

  /// Parses from a CBOR map representation.
  factory PublicKeyCredentialDescriptor.fromCbor(Map<dynamic, dynamic> cbor) {
    return PublicKeyCredentialDescriptor(
      type: cbor['type'] as String,
      id: (cbor['id'] as List).cast<int>(),
      transports: (cbor['transports'] as List?)?.cast<String>(),
    );
  }

  /// Serializes this descriptor to a CBOR map for CTAP.
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
