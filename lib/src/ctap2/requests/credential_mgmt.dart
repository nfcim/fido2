import 'package:cbor/cbor.dart';
import 'package:fido2/src/cose.dart';
import '../constants.dart';
import '../serialization.dart';
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
  static const int coseAlgorithmIdx = 0x80;

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

  /// COSE algorithm ID returned by the metadata-only extension.
  final int? coseAlgorithm;

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
    this.coseAlgorithm,
  });

  /// Decodes a CBOR-encoded response into [CredentialManagementResponse].
  static CredentialManagementResponse decode(
    List<int> data, {
    CoseConfiguration? configuration,
  }) {
    final encoded = ctapResponseMap(data);
    final rpMap = cborField<CborMap>(encoded, rpIdx);
    final userMap = cborField<CborMap>(encoded, userIdx);
    final credentialIdMap = cborField<CborMap>(encoded, credentialIdIdx);
    final publicKeyMap = cborField<CborMap>(encoded, publicKeyIdx);
    return CredentialManagementResponse(
      existingResidentCredentialsCount: cborField<CborInt>(
        encoded,
        existingResidentCredentialsCountIdx,
      )?.toInt(),
      maxPossibleRemainingResidentCredentialsCount: cborField<CborInt>(
        encoded,
        maxPossibleRemainingResidentCredentialsCountIdx,
      )?.toInt(),
      rp: rpMap != null
          ? PublicKeyCredentialRpEntity(
              id: cborField<CborString>(
                rpMap,
                'id',
                required: true,
              )!.toString(),
            )
          : null,
      rpIdHash: cborField<CborBytes>(encoded, rpIdHashIdx)?.bytes,
      totalRPs: cborField<CborInt>(encoded, totalRPsIdx)?.toInt(),
      user: userMap != null
          ? PublicKeyCredentialUserEntity(
              id: cborField<CborBytes>(userMap, 'id', required: true)!.bytes,
              name: cborField<CborString>(userMap, 'name')?.toString(),
              displayName: cborField<CborString>(
                userMap,
                'displayName',
              )?.toString(),
            )
          : null,
      credentialId: credentialIdMap != null
          ? PublicKeyCredentialDescriptor(
              transports: cborField<CborList>(credentialIdMap, 'transports')
                  ?.map((value) {
                    if (value is! CborString) {
                      throw const FormatException('Expected transport text');
                    }
                    return value.toString();
                  })
                  .toList(),
              type: cborField<CborString>(
                credentialIdMap,
                'type',
                required: true,
              )!.toString(),
              id: cborField<CborBytes>(
                credentialIdMap,
                'id',
                required: true,
              )!.bytes,
            )
          : null,
      publicKey: publicKeyMap != null
          ? CoseKey.fromCborMap(publicKeyMap, configuration: configuration)
          : null,
      totalCredentials: cborField<CborInt>(
        encoded,
        totalCredentialsIdx,
      )?.toInt(),
      credProtect: cborField<CborInt>(encoded, credProtectIdx)?.toInt(),
      coseAlgorithm: cborField<CborInt>(encoded, coseAlgorithmIdx)?.toInt(),
      largeBlobKey: cborField<CborBytes>(encoded, largeBlobKeyIdx)?.bytes,
    );
  }

  @override
  Map<String, dynamic> toJson() => _$CredentialManagementResponseToJson(this);
}
