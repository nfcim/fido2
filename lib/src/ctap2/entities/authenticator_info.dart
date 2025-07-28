import 'package:cbor/cbor.dart';

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
    map[1] = versions;
    if (extensions != null) {
      map[2] = extensions;
    }
    map[3] = aaguid;
    if (options != null) {
      map[4] = options;
    }
    if (maxMsgSize != null) {
      map[5] = maxMsgSize;
    }
    if (pinUvAuthProtocols != null) {
      map[6] = pinUvAuthProtocols;
    }
    if (maxCredentialCountInList != null) {
      map[7] = maxCredentialCountInList;
    }
    if (maxCredentialIdLength != null) {
      map[8] = maxCredentialIdLength;
    }
    if (transports != null) {
      map[9] = transports;
    }
    if (algorithms != null) {
      map[10] = algorithms;
    }
    if (maxSerializedLargeBlobArray != null) {
      map[11] = maxSerializedLargeBlobArray;
    }
    if (forcePinChange != null) {
      map[12] = forcePinChange;
    }
    if (minPinLength != null) {
      map[13] = minPinLength;
    }
    if (firmwareVersion != null) {
      map[14] = firmwareVersion;
    }
    if (maxCredBlobLength != null) {
      map[15] = maxCredBlobLength;
    }
    if (maxRpIdsForSetMinPinLength != null) {
      map[16] = maxRpIdsForSetMinPinLength;
    }
    if (preferredPlatformUvAttempts != null) {
      map[17] = preferredPlatformUvAttempts;
    }
    if (uvModality != null) {
      map[18] = uvModality;
    }
    if (certifications != null) {
      map[19] = certifications;
    }
    if (remainingDiscoverableCredentials != null) {
      map[20] = remainingDiscoverableCredentials;
    }
    if (vendorPrototypeConfigCommands != null) {
      map[21] = vendorPrototypeConfigCommands;
    }
    return cbor.encode(CborValue(map));
  }

  static AuthenticatorInfo decode(List<int> data) {
    final map = cbor.decode(data).toObject() as Map;
    return AuthenticatorInfo(
      versions: (map[1] as List).cast<String>(),
      extensions: (map[2] as List?)?.cast<String>(),
      aaguid: map[3] as List<int>,
      options: (map[4] as Map?)?.cast<String, bool>(),
      maxMsgSize: map[5] as int?,
      pinUvAuthProtocols: (map[6] as List?)?.cast<int>(),
      maxCredentialCountInList: map[7] as int?,
      maxCredentialIdLength: map[8] as int?,
      transports: (map[9] as List?)?.cast<String>(),
      algorithms: (map[10] as List?)?.cast<Map<String, int>>(),
      maxSerializedLargeBlobArray: map[11] as int?,
      forcePinChange: map[12] as bool?,
      minPinLength: map[13] as int?,
      firmwareVersion: map[14] as int?,
      maxCredBlobLength: map[15] as int?,
      maxRpIdsForSetMinPinLength: map[16] as int?,
      preferredPlatformUvAttempts: map[17] as int?,
      uvModality: map[18] as int?,
      certifications: (map[19] as Map?)?.cast<String, int>(),
      remainingDiscoverableCredentials: map[20] as int?,
      vendorPrototypeConfigCommands: (map[21] as List?)?.cast<int>(),
    );
  }
}
