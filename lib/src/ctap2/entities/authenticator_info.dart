import 'package:cbor/cbor.dart';
import 'package:fido2/src/utils/serialization.dart';
import 'package:json_annotation/json_annotation.dart';

part 'authenticator_info.g.dart';

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

  final List<String> versions;
  final List<String>? extensions;
  final List<int> aaguid;
  final Map<String, bool>? options;
  final int? maxMsgSize;
  final List<int>? pinUvAuthProtocols;
  final int? maxCredentialCountInList;
  final int? maxCredentialIdLength;
  final List<String>? transports;
  final List<Map<String, int>>? algorithms;
  final int? maxSerializedLargeBlobArray;
  final bool? forcePinChange;
  final int? minPinLength;
  final int? firmwareVersion;
  final int? maxCredBlobLength;
  final int? maxRpIdsForSetMinPinLength;
  final int? preferredPlatformUvAttempts;
  final int? uvModality;
  final Map<String, int>? certifications;
  final int? remainingDiscoverableCredentials;
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
