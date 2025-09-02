import 'package:cbor/cbor.dart';
import 'package:fido2/src/utils/serialization.dart';
import 'package:json_annotation/json_annotation.dart';
import '../constants.dart';
import '../entities/credential_entities.dart';

part 'make_credential.g.dart';

/// CTAP2 authenticatorMakeCredential (0x01) request (spec §6.1).
///
/// Requests generation of a new credential bound to an RP and user. Several
/// fields mirror WebAuthn makeCredential parameters.
@JsonSerializable(createFactory: false, explicitToJson: true)
class MakeCredentialRequest with JsonToStringMixin {
  static const int clientDataHashIdx = 1;
  static const int rpIdx = 2;
  static const int userIdx = 3;
  static const int pubKeyCredParamsIdx = 4;
  static const int excludeListIdx = 5;
  static const int extensionsIdx = 6;
  static const int optionsIdx = 7;
  static const int pinAuthIdx = 8;
  static const int pinProtocolIdx = 9;
  static const int enterpriseAttestationIdx = 10;

  /// Hash of serialized client data per WebAuthn.
  final List<int> clientDataHash;

  /// Relying Party entity to associate with the credential.
  final PublicKeyCredentialRpEntity rp;

  /// User entity to associate with the credential.
  final PublicKeyCredentialUserEntity user;

  /// Preferred algorithms for credential generation (ordered, no duplicates).
  final List<Map<String, dynamic>> pubKeyCredParams;

  /// Prevent duplicates by listing existing credentials for the account.
  final List<PublicKeyCredentialDescriptor>? excludeList;

  /// Extension inputs to influence authenticator operation.
  final Map<String, dynamic>? extensions;

  /// Additional boolean options (rk/up/uv) for operation.
  final Map<String, bool>? options;

  /// Result of authenticate(pinUvAuthToken, clientDataHash), if present.
  final List<int>? pinAuth;

  /// PIN/UV protocol version selected by the platform.
  final int? pinProtocol;

  /// Request enterprise attestation behavior if supported.
  final bool? enterpriseAttestation;

  MakeCredentialRequest({
    required this.clientDataHash,
    required this.rp,
    required this.user,
    required this.pubKeyCredParams,
    this.excludeList,
    this.extensions,
    this.options,
    this.pinAuth,
    this.pinProtocol,
    this.enterpriseAttestation,
  });

  /// Encodes this request as a CBOR map and prefixes the command byte.
  List<int> encode() {
    final map = <int, dynamic>{};
    map[clientDataHashIdx] = CborBytes(clientDataHash);
    map[rpIdx] = rp.toCbor();
    map[userIdx] = user.toCbor();
    map[pubKeyCredParamsIdx] =
        pubKeyCredParams.map((p) => CborValue(p)).toList();
    if (excludeList != null && excludeList!.isNotEmpty) {
      map[excludeListIdx] = excludeList!.map((e) => e.toCbor()).toList();
    }
    if (extensions != null) {
      map[extensionsIdx] = CborValue(extensions!);
    }
    if (options != null) {
      map[optionsIdx] = CborValue(options!);
    }
    if (pinAuth != null) {
      map[pinAuthIdx] = CborBytes(pinAuth!);
    }
    if (pinProtocol != null) {
      map[pinProtocolIdx] = pinProtocol!;
    }
    if (enterpriseAttestation != null) {
      map[enterpriseAttestationIdx] = enterpriseAttestation!;
    }
    return [Ctap2Commands.makeCredential.value] + cbor.encode(CborValue(map));
  }

  @override
  Map<String, dynamic> toJson() => _$MakeCredentialRequestToJson(this);
}

/// CTAP2 authenticatorMakeCredential (0x01) response (spec §6.1).
///
/// Returns attestation format, authenticator data, attestation statement and
/// optional enterprise attestation and large-blob key.
@JsonSerializable(createFactory: false, explicitToJson: true)
class MakeCredentialResponse with JsonToStringMixin {
  static const int fmtIdx = 1;
  static const int authDataIdx = 2;
  static const int attStmtIdx = 3;
  static const int epAttIdx = 4;
  static const int largeBlobKeyIdx = 5;

  /// Attestation statement format identifier.
  final String fmt;

  /// Raw authenticator data buffer.
  final List<int> authData;

  /// Attestation statement object.
  final Map<String, dynamic> attStmt;

  /// Whether enterprise attestation was performed.
  final bool? epAtt;

  /// Large-blob encryption key, if provided.
  final List<int>? largeBlobKey;

  MakeCredentialResponse({
    required this.fmt,
    required this.authData,
    required this.attStmt,
    this.epAtt,
    this.largeBlobKey,
  });

  /// Decodes a CBOR-encoded response into [MakeCredentialResponse].
  static MakeCredentialResponse decode(List<int> data) {
    final map = cbor.decode(data).toObject() as Map;
    return MakeCredentialResponse(
      fmt: map[fmtIdx] as String,
      authData: (map[authDataIdx] as List?)?.cast<int>() ?? [],
      attStmt: (map[attStmtIdx] as Map?)?.cast<String, dynamic>() ?? {},
      epAtt: map[epAttIdx] as bool?,
      largeBlobKey: (map[largeBlobKeyIdx] as List?)?.cast<int>(),
    );
  }

  @override
  Map<String, dynamic> toJson() => _$MakeCredentialResponseToJson(this);
}
