import 'package:cbor/cbor.dart';
import 'package:fido2/src/cose.dart';
import '../constants.dart';
import '../entities/credential_entities.dart';
import 'package:fido2/src/utils/serialization.dart';
import 'package:json_annotation/json_annotation.dart';

part 'credential_mgmt.g.dart';

/// CTAP2 authenticatorCredentialManagement (0x0A) request (spec §6.8).
///
/// Manages discoverable credentials on the authenticator (enumerate, delete,
/// update, etc.).
@JsonSerializable(createFactory: false, explicitToJson: true)
class CredentialManagementRequest with JsonToStringMixin {
  static const int subCmdIdx = 1;
  static const int paramsIdx = 2;
  static const int pinUvAuthProtocolIdx = 3;
  static const int pinUvAuthParamIdx = 4;

  /// The credential management subCommand being requested.
  final int subCommand;

  /// Parameters CBOR map for the subCommand.
  final CborMap? params;

  /// PIN/UV protocol version chosen by the platform.
  final int? pinUvAuthProtocol;

  /// HMAC-SHA-256 (first 16 bytes) over contents using pinUvAuthToken.
  final List<int>? pinUvAuthParam;

  CredentialManagementRequest({
    required this.subCommand,
    this.params,
    this.pinUvAuthProtocol,
    this.pinUvAuthParam,
  });

  /// Encodes this request as a CBOR map and prefixes the command byte.
  List<int> encode() {
    final map = <int, dynamic>{};
    map[subCmdIdx] = subCommand;
    if (params != null) {
      map[paramsIdx] = params;
    }
    if (pinUvAuthProtocol != null) {
      map[pinUvAuthProtocolIdx] = pinUvAuthProtocol!;
    }
    if (pinUvAuthParam != null) {
      map[pinUvAuthParamIdx] = CborBytes(pinUvAuthParam!);
    }
    return [Ctap2Commands.credentialManagement.value] +
        cbor.encode(CborValue(map));
  }

  @override
  Map<String, dynamic> toJson() => _$CredentialManagementRequestToJson(this);
}

/// CTAP2 authenticatorCredentialManagement (0x0A) response (spec §6.8).
///
/// Returns RP/user/credential information, counts, and key material depending
/// on the subCommand.
@JsonSerializable(createFactory: false, explicitToJson: true)
class CredentialManagementResponse with JsonToStringMixin {
  static const int existingResidentCredentialsCountIdx = 1;
  static const int maxPossibleRemainingResidentCredentialsCountIdx = 2;
  static const int rpIdx = 3;
  static const int rpIdHashIdx = 4;
  static const int totalRPsIdx = 5;
  static const int userIdx = 6;
  static const int credentialIdIdx = 7;
  static const int publicKeyIdx = 8;
  static const int totalCredentialsIdx = 9;
  static const int credProtectIdx = 10;
  static const int largeBlobKeyIdx = 11;

  /// Number of existing discoverable credentials on the authenticator.
  final int? existingResidentCredentialsCount;

  /// Maximum additional discoverable credentials possible.
  final int? maxPossibleRemainingResidentCredentialsCount;

  /// Relying Party information.
  final PublicKeyCredentialRpEntity? rp;

  /// SHA-256 hash of the RP ID.
  final List<int>? rpIdHash;

  /// Total number of RPs present on the authenticator.
  final int? totalRPs;

  /// User information.
  final PublicKeyCredentialUserEntity? user;

  /// Credential identifier.
  final PublicKeyCredentialDescriptor? credentialId;

  /// Credential public key (COSE_Key).
  final CoseKey? publicKey;

  /// Total number of credentials for the RP.
  final int? totalCredentials;

  /// Credential protection policy value.
  final int? credProtect;

  /// Large blob encryption key.
  final List<int>? largeBlobKey;

  CredentialManagementResponse({
    this.existingResidentCredentialsCount,
    this.maxPossibleRemainingResidentCredentialsCount,
    this.rp,
    this.rpIdHash,
    this.totalRPs,
    this.user,
    this.credentialId,
    this.publicKey,
    this.totalCredentials,
    this.credProtect,
    this.largeBlobKey,
  });

  /// Decodes a CBOR-encoded response into [CredentialManagementResponse].
  static CredentialManagementResponse decode(List<int> data) {
    final map = cbor.decode(data).toObject() as Map;
    final rpMap = (map[rpIdx] as Map?)?.cast<String, dynamic>();
    final userMap = (map[userIdx] as Map?)?.cast<String, dynamic>();
    final credentialIdMap =
        (map[credentialIdIdx] as Map?)?.cast<String, dynamic>();
    final publicKeyMap = (map[publicKeyIdx] as Map?)?.cast<int, dynamic>();
    return CredentialManagementResponse(
      existingResidentCredentialsCount:
          map[existingResidentCredentialsCountIdx] as int?,
      maxPossibleRemainingResidentCredentialsCount:
          map[maxPossibleRemainingResidentCredentialsCountIdx] as int?,
      rp: rpMap != null ? PublicKeyCredentialRpEntity.fromCbor(rpMap) : null,
      rpIdHash: (map[rpIdHashIdx] as List?)?.cast<int>(),
      totalRPs: map[totalRPsIdx] as int?,
      user: userMap != null
          ? PublicKeyCredentialUserEntity.fromCbor(userMap)
          : null,
      credentialId: credentialIdMap != null
          ? PublicKeyCredentialDescriptor.fromCbor(credentialIdMap)
          : null,
      publicKey: publicKeyMap != null ? CoseKey.parse(publicKeyMap) : null,
      totalCredentials: map[totalCredentialsIdx] as int?,
      credProtect: map[credProtectIdx] as int?,
      largeBlobKey: (map[largeBlobKeyIdx] as List?)?.cast<int>(),
    );
  }

  @override
  Map<String, dynamic> toJson() => _$CredentialManagementResponseToJson(this);
}
