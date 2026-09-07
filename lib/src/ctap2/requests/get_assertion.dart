import 'package:cbor/cbor.dart';
import '../serialization.dart';
import '../constants.dart';
import '../entities/credential_entities.dart';
import 'package:fido2/src/utils/serialization.dart';
import 'package:json_annotation/json_annotation.dart';

part 'get_assertion.g.dart';

/// CTAP2 authenticatorGetAssertion (0x02) request (spec §6.2).
///
/// Requests an assertion for a given RP using a previously created credential.
@JsonSerializable(createFactory: false, explicitToJson: true)
class GetAssertionRequest with JsonToStringMixin {
  static const int rpIdIdx = 1;
  static const int clientDataHashIdx = 2;
  static const int allowListIdx = 3;
  static const int extensionsIdx = 4;
  static const int optionsIdx = 5;
  static const int pinAuthIdx = 6;
  static const int pinProtocolIdx = 7;

  /// Relying party identifier.
  final String rpId;

  /// Hash of the serialized client data.
  final List<int> clientDataHash;

  /// Optional allow-list of credentials to constrain selection.
  final List<PublicKeyCredentialDescriptor>? allowList;

  /// Extension inputs to influence authenticator operation.
  final Map<String, dynamic>? extensions;

  /// Options map, e.g., {"up": true, "uv": false}.
  final Map<String, bool>? options;

  /// Result of authenticateParam(pinUvAuthToken, clientDataHash):
  /// 16 bytes for PIN v1, 32 bytes for PIN v2.
  final List<int>? pinAuth;

  /// PIN/UV protocol version selected by the platform.
  final int? pinProtocol;

  GetAssertionRequest({
    required this.rpId,
    required this.clientDataHash,
    this.allowList,
    this.extensions,
    this.options,
    this.pinAuth,
    this.pinProtocol,
  });

  /// Encodes this request as a CBOR map and prefixes the command byte.
  List<int> encode() {
    final map = <int, dynamic>{};
    map[rpIdIdx] = CborString(rpId);
    map[clientDataHashIdx] = CborBytes(clientDataHash);

    if (allowList != null && allowList!.isNotEmpty) {
      map[allowListIdx] = allowList!.map((a) => a.toCbor()).toList();
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

    return [Ctap2Commands.getAssertion.value] + cbor.encode(CborValue(map));
  }

  @override
  Map<String, dynamic> toJson() => _$GetAssertionRequestToJson(this);
}

/// CTAP2 authenticatorGetAssertion (0x02) response (spec §6.2).
///
/// Returns the selected credential descriptor, authenticator data, signature,
/// and optional user information and counts.
@JsonSerializable(createFactory: false, explicitToJson: true)
class GetAssertionResponse with JsonToStringMixin {
  static const int credentialIdx = 1;
  static const int authDataIdx = 2;
  static const int signatureIdx = 3;
  static const int userIdx = 4;
  static const int numberOfCredentialsIdx = 5;
  static const int userSelectedIdx = 6;
  static const int largeBlobKeyIdx = 7;

  /// Credential used for the assertion.
  final PublicKeyCredentialDescriptor credential;

  /// Raw authenticator data buffer.
  final List<int> authData;

  /// Assertion signature.
  final List<int> signature;

  /// Optional user entity information.
  final PublicKeyCredentialUserEntity? user;

  /// Number of available credentials for subsequent getNextAssertion.
  final int? numberOfCredentials;

  /// Whether the user actively selected a credential.
  final bool? userSelected;

  /// Large-blob encryption key, if provided.
  final List<int>? largeBlobKey;

  GetAssertionResponse({
    required this.credential,
    required this.authData,
    required this.signature,
    this.user,
    this.numberOfCredentials,
    this.userSelected,
    this.largeBlobKey,
  });

  /// Decodes a CBOR-encoded response into [GetAssertionResponse].
  /// Supply [requestedCredential] when the authenticator omits the descriptor
  /// for a request with exactly one allowed credential.
  static GetAssertionResponse decode(
    List<int> data, {
    PublicKeyCredentialDescriptor? requestedCredential,
  }) {
    final map = ctapResponseMap(data);
    final descriptor = cborField<CborMap>(map, credentialIdx);
    final user = cborField<CborMap>(map, userIdx);
    final credential = descriptor == null
        ? requestedCredential
        : PublicKeyCredentialDescriptor(
            type: cborField<CborString>(
              descriptor,
              'type',
              required: true,
            )!.toString(),
            id: cborField<CborBytes>(descriptor, 'id', required: true)!.bytes,
          );
    if (credential == null) {
      throw const FormatException(
        'Credential descriptor or single requested credential required',
      );
    }
    return GetAssertionResponse(
      credential: credential,
      authData: cborField<CborBytes>(map, authDataIdx, required: true)!.bytes,
      signature: cborField<CborBytes>(map, signatureIdx, required: true)!.bytes,
      user: user == null
          ? null
          : PublicKeyCredentialUserEntity(
              id: cborField<CborBytes>(user, 'id', required: true)!.bytes,
              name: cborField<CborString>(user, 'name')?.toString(),
              displayName: cborField<CborString>(
                user,
                'displayName',
              )?.toString(),
            ),
      numberOfCredentials: cborField<CborInt>(
        map,
        numberOfCredentialsIdx,
      )?.toInt(),
      userSelected:
          cborField<CborBool>(map, userSelectedIdx)?.toObject() as bool?,
      largeBlobKey: cborField<CborBytes>(map, largeBlobKeyIdx)?.bytes,
    );
  }

  @override
  Map<String, dynamic> toJson() => _$GetAssertionResponseToJson(this);
}
