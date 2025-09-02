import 'package:cbor/cbor.dart';
import 'package:fido2/src/utils/serialization.dart';
import 'package:json_annotation/json_annotation.dart';

part 'authenticator_info.g.dart';

/// CTAP2 authenticatorGetInfo response structure (spec §6.4).
///
/// Represents the authenticator's capabilities and preferences reported via
/// the `getInfo` command. Platforms should use this to tailor subsequent
/// requests. Field meanings follow the CTAP2 specification.
@JsonSerializable(createFactory: false)
class AuthenticatorInfo with JsonToStringMixin {
  static const int versionsIdx = 1;
  static const int extensionsIdx = 2;
  static const int aaguidIdx = 3;
  static const int optionsIdx = 4;
  static const int maxMsgSizeIdx = 5;
  static const int pinUvAuthProtocolsIdx = 6;
  static const int maxCredentialCountInListIdx = 7;
  static const int maxCredentialIdLengthIdx = 8;
  static const int transportsIdx = 9;
  static const int algorithmsIdx = 10;
  static const int maxSerializedLargeBlobArrayIdx = 11;
  static const int forcePinChangeIdx = 12;
  static const int minPinLengthIdx = 13;
  static const int firmwareVersionIdx = 14;
  static const int maxCredBlobLengthIdx = 15;
  static const int maxRpIdsForSetMinPinLengthIdx = 16;
  static const int preferredPlatformUvAttemptsIdx = 17;
  static const int uvModalityIdx = 18;
  static const int certificationsIdx = 19;
  static const int remainingDiscoverableCredentialsIdx = 20;
  static const int vendorPrototypeConfigCommandsIdx = 21;

  /// List of supported versions (e.g. "FIDO_2_1", "FIDO_2_0", "U2F_V2").
  final List<String> versions;

  /// List of supported extensions, if any.
  final List<String>? extensions;

  /// The claimed AAGUID (16 bytes).
  final List<int> aaguid;

  /// Map of supported options and their boolean values.
  final Map<String, bool>? options;

  /// Maximum message size supported by the authenticator.
  final int? maxMsgSize;

  /// Supported PIN/UV auth protocols in order of preference.
  final List<int>? pinUvAuthProtocols;

  /// Maximum number of credentials accepted in a list.
  final int? maxCredentialCountInList;

  /// Maximum credential ID length.
  final int? maxCredentialIdLength;

  /// Supported transports (mirrors WebAuthn `AuthenticatorTransport`).
  final List<String>? transports;

  /// Supported algorithms for credential generation (most- to least-preferred).
  final List<Map<String, int>>? algorithms;

  /// Maximum size in bytes of serialized large-blob array, if supported.
  final int? maxSerializedLargeBlobArray;

  /// Whether a PIN change is required before certain operations.
  final bool? forcePinChange;

  /// Minimum PIN length (Unicode code points) for ClientPIN.
  final int? minPinLength;

  /// Firmware version for the authenticator model.
  final int? firmwareVersion;

  /// Maximum `credBlob` length in bytes, if extension supported.
  final int? maxCredBlobLength;

  /// Maximum number of RP IDs accepted by setMinPINLength subcommand.
  final int? maxRpIdsForSetMinPinLength;

  /// Preferred number of UV attempts before fallback to PIN.
  final int? preferredPlatformUvAttempts;

  /// User verification modality bit flags per FIDO Registry.
  final int? uvModality;

  /// Creates an [AuthenticatorInfo] with values reported by the authenticator.
  /// Authenticator certifications.
  final Map<String, int>? certifications;

  /// Estimated number of additional discoverable credentials that can be stored.
  final int? remainingDiscoverableCredentials;

  /// List of supported vendor prototype config command IDs.
  final List<int>? vendorPrototypeConfigCommands;

  AuthenticatorInfo({
    required this.versions,
    this.extensions,
    required this.aaguid,
    this.options,
    this.maxMsgSize,
    this.pinUvAuthProtocols,
    this.maxCredentialCountInList,
    this.maxCredentialIdLength,
    this.transports,
    this.algorithms,
    this.maxSerializedLargeBlobArray,
    this.forcePinChange,
    this.minPinLength,
    this.firmwareVersion,
    this.maxCredBlobLength,
    this.maxRpIdsForSetMinPinLength,
    this.preferredPlatformUvAttempts,
    this.uvModality,
    this.certifications,
    this.remainingDiscoverableCredentials,
    this.vendorPrototypeConfigCommands,
  });

  /// Encodes this structure to a CBOR map as defined by CTAP2 getInfo.
  List<int> encode() {
    final map = <int, dynamic>{};
    map[versionsIdx] = versions;
    if (extensions != null) {
      map[extensionsIdx] = extensions;
    }
    map[aaguidIdx] = aaguid;
    if (options != null) {
      map[optionsIdx] = options;
    }
    if (maxMsgSize != null) {
      map[maxMsgSizeIdx] = maxMsgSize;
    }
    if (pinUvAuthProtocols != null) {
      map[pinUvAuthProtocolsIdx] = pinUvAuthProtocols;
    }
    if (maxCredentialCountInList != null) {
      map[maxCredentialCountInListIdx] = maxCredentialCountInList;
    }
    if (maxCredentialIdLength != null) {
      map[maxCredentialIdLengthIdx] = maxCredentialIdLength;
    }
    if (transports != null) {
      map[transportsIdx] = transports;
    }
    if (algorithms != null) {
      map[algorithmsIdx] = algorithms;
    }
    if (maxSerializedLargeBlobArray != null) {
      map[maxSerializedLargeBlobArrayIdx] = maxSerializedLargeBlobArray;
    }
    if (forcePinChange != null) {
      map[forcePinChangeIdx] = forcePinChange;
    }
    if (minPinLength != null) {
      map[minPinLengthIdx] = minPinLength;
    }
    if (firmwareVersion != null) {
      map[firmwareVersionIdx] = firmwareVersion;
    }
    if (maxCredBlobLength != null) {
      map[maxCredBlobLengthIdx] = maxCredBlobLength;
    }
    if (maxRpIdsForSetMinPinLength != null) {
      map[maxRpIdsForSetMinPinLengthIdx] = maxRpIdsForSetMinPinLength;
    }
    if (preferredPlatformUvAttempts != null) {
      map[preferredPlatformUvAttemptsIdx] = preferredPlatformUvAttempts;
    }
    if (uvModality != null) {
      map[uvModalityIdx] = uvModality;
    }
    if (certifications != null) {
      map[certificationsIdx] = certifications;
    }
    if (remainingDiscoverableCredentials != null) {
      map[remainingDiscoverableCredentialsIdx] =
          remainingDiscoverableCredentials;
    }
    if (vendorPrototypeConfigCommands != null) {
      map[vendorPrototypeConfigCommandsIdx] = vendorPrototypeConfigCommands;
    }
    return cbor.encode(CborValue(map));
  }

  /// Decodes a CBOR-encoded authenticatorGetInfo response into [AuthenticatorInfo].
  static AuthenticatorInfo decode(List<int> data) {
    final map = cbor.decode(data).toObject() as Map;
    return AuthenticatorInfo(
      versions: (map[versionsIdx] as List).cast<String>(),
      extensions: (map[extensionsIdx] as List?)?.cast<String>(),
      aaguid: map[aaguidIdx] as List<int>,
      options: (map[optionsIdx] as Map?)?.cast<String, bool>(),
      maxMsgSize: map[maxMsgSizeIdx] as int?,
      pinUvAuthProtocols: (map[pinUvAuthProtocolsIdx] as List?)?.cast<int>(),
      maxCredentialCountInList: map[maxCredentialCountInListIdx] as int?,
      maxCredentialIdLength: map[maxCredentialIdLengthIdx] as int?,
      transports: (map[transportsIdx] as List?)?.cast<String>(),
      algorithms: (map[algorithmsIdx] as List?)?.cast<Map<String, int>>(),
      maxSerializedLargeBlobArray: map[maxSerializedLargeBlobArrayIdx] as int?,
      forcePinChange: map[forcePinChangeIdx] as bool?,
      minPinLength: map[minPinLengthIdx] as int?,
      firmwareVersion: map[firmwareVersionIdx] as int?,
      maxCredBlobLength: map[maxCredBlobLengthIdx] as int?,
      maxRpIdsForSetMinPinLength: map[maxRpIdsForSetMinPinLengthIdx] as int?,
      preferredPlatformUvAttempts: map[preferredPlatformUvAttemptsIdx] as int?,
      uvModality: map[uvModalityIdx] as int?,
      certifications: (map[certificationsIdx] as Map?)?.cast<String, int>(),
      remainingDiscoverableCredentials:
          map[remainingDiscoverableCredentialsIdx] as int?,
      vendorPrototypeConfigCommands:
          (map[vendorPrototypeConfigCommandsIdx] as List?)?.cast<int>(),
    );
  }

  @override
  Map<String, dynamic> toJson() => _$AuthenticatorInfoToJson(this);
}
