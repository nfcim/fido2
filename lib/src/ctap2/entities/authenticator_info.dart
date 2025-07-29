import 'package:cbor/cbor.dart';
import 'package:convert/convert.dart';

import '../constants.dart';

class AuthenticatorInfo {
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
    map[authInfoVersionsIdx] = versions;
    if (extensions != null) {
      map[authInfoExtensionsIdx] = extensions;
    }
    map[authInfoAaguidIdx] = aaguid;
    if (options != null) {
      map[authInfoOptionsIdx] = options;
    }
    if (maxMsgSize != null) {
      map[authInfoMaxMsgSizeIdx] = maxMsgSize;
    }
    if (pinUvAuthProtocols != null) {
      map[authInfoPinUvAuthProtocolsIdx] = pinUvAuthProtocols;
    }
    if (maxCredentialCountInList != null) {
      map[authInfoMaxCredentialCountInListIdx] = maxCredentialCountInList;
    }
    if (maxCredentialIdLength != null) {
      map[authInfoMaxCredentialIdLengthIdx] = maxCredentialIdLength;
    }
    if (transports != null) {
      map[authInfoTransportsIdx] = transports;
    }
    if (algorithms != null) {
      map[authInfoAlgorithmsIdx] = algorithms;
    }
    if (maxSerializedLargeBlobArray != null) {
      map[authInfoMaxSerializedLargeBlobArrayIdx] = maxSerializedLargeBlobArray;
    }
    if (forcePinChange != null) {
      map[authInfoForcePinChangeIdx] = forcePinChange;
    }
    if (minPinLength != null) {
      map[authInfoMinPinLengthIdx] = minPinLength;
    }
    if (firmwareVersion != null) {
      map[authInfoFirmwareVersionIdx] = firmwareVersion;
    }
    if (maxCredBlobLength != null) {
      map[authInfoMaxCredBlobLengthIdx] = maxCredBlobLength;
    }
    if (maxRpIdsForSetMinPinLength != null) {
      map[authInfoMaxRpIdsForSetMinPinLengthIdx] = maxRpIdsForSetMinPinLength;
    }
    if (preferredPlatformUvAttempts != null) {
      map[authInfoPreferredPlatformUvAttemptsIdx] = preferredPlatformUvAttempts;
    }
    if (uvModality != null) {
      map[authInfoUvModalityIdx] = uvModality;
    }
    if (certifications != null) {
      map[authInfoCertificationsIdx] = certifications;
    }
    if (remainingDiscoverableCredentials != null) {
      map[authInfoRemainingDiscoverableCredentialsIdx] =
          remainingDiscoverableCredentials;
    }
    if (vendorPrototypeConfigCommands != null) {
      map[authInfoVendorPrototypeConfigCommandsIdx] =
          vendorPrototypeConfigCommands;
    }
    return cbor.encode(CborValue(map));
  }

  static AuthenticatorInfo decode(List<int> data) {
    final map = cbor.decode(data).toObject() as Map;
    return AuthenticatorInfo(
      versions: (map[authInfoVersionsIdx] as List).cast<String>(),
      extensions: (map[authInfoExtensionsIdx] as List?)?.cast<String>(),
      aaguid: map[authInfoAaguidIdx] as List<int>,
      options: (map[authInfoOptionsIdx] as Map?)?.cast<String, bool>(),
      maxMsgSize: map[authInfoMaxMsgSizeIdx] as int?,
      pinUvAuthProtocols:
          (map[authInfoPinUvAuthProtocolsIdx] as List?)?.cast<int>(),
      maxCredentialCountInList:
          map[authInfoMaxCredentialCountInListIdx] as int?,
      maxCredentialIdLength: map[authInfoMaxCredentialIdLengthIdx] as int?,
      transports: (map[authInfoTransportsIdx] as List?)?.cast<String>(),
      algorithms:
          (map[authInfoAlgorithmsIdx] as List?)?.cast<Map<String, int>>(),
      maxSerializedLargeBlobArray:
          map[authInfoMaxSerializedLargeBlobArrayIdx] as int?,
      forcePinChange: map[authInfoForcePinChangeIdx] as bool?,
      minPinLength: map[authInfoMinPinLengthIdx] as int?,
      firmwareVersion: map[authInfoFirmwareVersionIdx] as int?,
      maxCredBlobLength: map[authInfoMaxCredBlobLengthIdx] as int?,
      maxRpIdsForSetMinPinLength:
          map[authInfoMaxRpIdsForSetMinPinLengthIdx] as int?,
      preferredPlatformUvAttempts:
          map[authInfoPreferredPlatformUvAttemptsIdx] as int?,
      uvModality: map[authInfoUvModalityIdx] as int?,
      certifications:
          (map[authInfoCertificationsIdx] as Map?)?.cast<String, int>(),
      remainingDiscoverableCredentials:
          map[authInfoRemainingDiscoverableCredentialsIdx] as int?,
      vendorPrototypeConfigCommands:
          (map[authInfoVendorPrototypeConfigCommandsIdx] as List?)?.cast<int>(),
    );
  }

  @override
  String toString() {
    final buffer = StringBuffer();
    buffer.writeln('AuthenticatorInfo(');
    buffer.writeln('  versions: $versions,');
    buffer.writeln('  aaguid: ${hex.encode(aaguid)},');

    if (extensions != null) buffer.writeln('  extensions: $extensions,');
    if (options != null) buffer.writeln('  options: $options,');
    if (maxMsgSize != null) buffer.writeln('  maxMsgSize: $maxMsgSize,');
    if (pinUvAuthProtocols != null) {
      buffer.writeln('  pinUvAuthProtocols: $pinUvAuthProtocols,');
    }
    if (maxCredentialCountInList != null) {
      buffer.writeln('  maxCredentialCountInList: $maxCredentialCountInList,');
    }
    if (maxCredentialIdLength != null) {
      buffer.writeln('  maxCredentialIdLength: $maxCredentialIdLength,');
    }
    if (transports != null) buffer.writeln('  transports: $transports,');
    if (algorithms != null) buffer.writeln('  algorithms: $algorithms,');
    if (maxSerializedLargeBlobArray != null) {
      buffer.writeln(
          '  maxSerializedLargeBlobArray: $maxSerializedLargeBlobArray,');
    }
    if (forcePinChange != null) {
      buffer.writeln('  forcePinChange: $forcePinChange,');
    }
    if (minPinLength != null) buffer.writeln('  minPinLength: $minPinLength,');
    if (firmwareVersion != null) {
      buffer.writeln('  firmwareVersion: $firmwareVersion,');
    }
    if (maxCredBlobLength != null) {
      buffer.writeln('  maxCredBlobLength: $maxCredBlobLength,');
    }
    if (maxRpIdsForSetMinPinLength != null) {
      buffer.writeln(
          '  maxRpIdsForSetMinPinLength: $maxRpIdsForSetMinPinLength,');
    }
    if (preferredPlatformUvAttempts != null) {
      buffer.writeln(
          '  preferredPlatformUvAttempts: $preferredPlatformUvAttempts,');
    }
    if (uvModality != null) buffer.writeln('  uvModality: $uvModality,');
    if (certifications != null) {
      buffer.writeln('  certifications: $certifications,');
    }
    if (remainingDiscoverableCredentials != null) {
      buffer.writeln(
          '  remainingDiscoverableCredentials: $remainingDiscoverableCredentials,');
    }
    if (vendorPrototypeConfigCommands != null) {
      buffer.writeln(
          '  vendorPrototypeConfigCommands: $vendorPrototypeConfigCommands,');
    }

    buffer.write(')');
    return buffer.toString();
  }
}
