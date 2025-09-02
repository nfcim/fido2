import 'package:cbor/cbor.dart';
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

  /// Result of authenticate(pinUvAuthToken, clientDataHash), if present.
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
  static GetAssertionResponse decode(List<int> data) {
    final map = cbor.decode(data).toObject() as Map;
    final credentialMap = map[credentialIdx] as Map?;
    return GetAssertionResponse(
      credential: PublicKeyCredentialDescriptor(
        type: credentialMap?['type'] as String? ?? '',
        id: (credentialMap?['id'] as List?)?.cast<int>() ?? [],
      ),
      authData: (map[authDataIdx] as List?)?.cast<int>() ?? [],
      signature: (map[signatureIdx] as List?)?.cast<int>() ?? [],
      user: (map[userIdx] as Map?)?.cast<String, dynamic>() != null
          ? PublicKeyCredentialUserEntity.fromCbor(map[userIdx])
          : null,
      numberOfCredentials: map[numberOfCredentialsIdx] as int?,
      userSelected: map[userSelectedIdx] as bool?,
      largeBlobKey: (map[largeBlobKeyIdx] as List?)?.cast<int>(),
    );
  }

  @override
  Map<String, dynamic> toJson() => _$GetAssertionResponseToJson(this);
}
