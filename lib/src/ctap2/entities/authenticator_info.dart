import 'package:cbor/cbor.dart';
import '../serialization.dart';
import '../../strict_cbor.dart';
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
  final List<Map<String, dynamic>>? algorithms;

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
    map[aaguidIdx] = CborBytes(aaguid);
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
    final map = ctapResponseMap(data);
    List<T>? list<T>(
      int label,
      T Function(CborValue) convert, {
      bool required = false,
    }) {
      return cborField<CborList>(
        map,
        label,
        required: required,
      )?.map(convert).toList();
    }

    String text(CborValue value) {
      if (value is! CborString || value.tags.isNotEmpty) {
        throw const FormatException('Expected untagged CTAP text');
      }
      return value.toString();
    }

    int integer(CborValue value) {
      if (value is! CborInt || value.tags.isNotEmpty) {
        throw const FormatException('Expected untagged CTAP integer');
      }
      return cborExactInt(value);
    }

    bool boolean(CborValue value) {
      if (value is! CborBool || value.tags.isNotEmpty) {
        throw const FormatException('Expected untagged CTAP boolean');
      }
      return value.toObject() as bool;
    }

    int? number(int label) {
      final value = cborField<CborInt>(map, label);
      return value == null ? null : integer(value);
    }

    Map<String, T>? dictionary<T>(int label, T Function(CborValue) convert) {
      final value = cborField<CborMap>(map, label);
      return value == null
          ? null
          : {
              for (final entry in value.entries)
                text(entry.key): convert(entry.value),
            };
    }

    final aaguid = cborField<CborBytes>(map, aaguidIdx, required: true)!.bytes;
    if (aaguid.length != 16) {
      throw const FormatException('Expected 16-byte AAGUID');
    }
    return AuthenticatorInfo(
      versions: list(versionsIdx, text, required: true)!,
      extensions: list(extensionsIdx, text),
      aaguid: aaguid,
      options: dictionary(optionsIdx, boolean),
      maxMsgSize: number(maxMsgSizeIdx),
      pinUvAuthProtocols: list(pinUvAuthProtocolsIdx, integer),
      maxCredentialCountInList: number(maxCredentialCountInListIdx),
      maxCredentialIdLength: number(maxCredentialIdLengthIdx),
      transports: list(transportsIdx, text),
      algorithms: list(algorithmsIdx, (entry) {
        if (entry is! CborMap || entry.tags.isNotEmpty) {
          throw const FormatException('Expected CTAP algorithm map');
        }
        final result = <String, dynamic>{
          for (final item in entry.entries)
            text(item.key): item.value.toObject(),
        };
        result['type'] = text(
          cborField<CborString>(entry, 'type', required: true)!,
        );
        result['alg'] = integer(
          cborField<CborInt>(entry, 'alg', required: true)!,
        );
        return result;
      }),
      maxSerializedLargeBlobArray: number(maxSerializedLargeBlobArrayIdx),
      forcePinChange:
          cborField<CborBool>(map, forcePinChangeIdx)?.toObject() as bool?,
      minPinLength: number(minPinLengthIdx),
      firmwareVersion: number(firmwareVersionIdx),
      maxCredBlobLength: number(maxCredBlobLengthIdx),
      maxRpIdsForSetMinPinLength: number(maxRpIdsForSetMinPinLengthIdx),
      preferredPlatformUvAttempts: number(preferredPlatformUvAttemptsIdx),
      uvModality: number(uvModalityIdx),
      certifications: dictionary(certificationsIdx, integer),
      remainingDiscoverableCredentials: number(
        remainingDiscoverableCredentialsIdx,
      ),
      vendorPrototypeConfigCommands: list(
        vendorPrototypeConfigCommandsIdx,
        integer,
      ),
    );
  }

  @override
  Map<String, dynamic> toJson() => _$AuthenticatorInfoToJson(this);
}
