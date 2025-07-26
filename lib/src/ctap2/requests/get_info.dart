import 'package:cbor/cbor.dart';
import '../constants.dart';
import '../entities/authenticator_info.dart';

class GetInfoUtils {
  /// Make the request to get info from the authenticator.
  static List<int> makeGetInfoRequest() {
    return [Ctap2Commands.getInfo.value];
  }

  /// Parse the response from the authenticator.
  static AuthenticatorInfo parseGetInfoResponse(List<int> data) {
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