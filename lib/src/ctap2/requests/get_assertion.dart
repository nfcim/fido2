import 'package:cbor/cbor.dart';
import '../constants.dart';
import '../entities/credential_entities.dart';

class GetAssertionRequest {
  final String rpId;
  final List<int> clientDataHash;
  final List<PublicKeyCredentialDescriptor>? allowList;
  final Map<String, dynamic>? extensions;
  final Map<String, bool>? options;
  final List<int>? pinAuth;
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
}

class GetAssertionResponse {
  final PublicKeyCredentialDescriptor credential;
  final List<int> authData;
  final List<int> signature;
  final PublicKeyCredentialUserEntity? user;
  final int? numberOfCredentials;
  final bool? userSelected;
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
}

class GetAssertionUtils {
  static List<int> makeGetAssertionRequest(GetAssertionRequest request) {
    final map = <int, dynamic>{};
    map[1] = CborString(request.rpId);
    map[2] = CborBytes(request.clientDataHash);

    if (request.allowList != null && request.allowList!.isNotEmpty) {
      map[3] = request.allowList!.map((a) => a.toCbor()).toList();
    }
    if (request.extensions != null) {
      map[4] = CborValue(request.extensions!);
    }
    if (request.options != null) {
      map[5] = CborValue(request.options!);
    }
    if (request.pinAuth != null) {
      map[6] = CborBytes(request.pinAuth!);
    }
    if (request.pinProtocol != null) {
      map[7] = request.pinProtocol!;
    }

    return [Ctap2Commands.getAssertion.value] + cbor.encode(CborValue(map));
  }

  static GetAssertionResponse parseGetAssertionResponse(List<int> data) {
    final map = cbor.decode(data).toObject() as Map;
    final credentialMap = map[1] as Map?;
    return GetAssertionResponse(
      credential: PublicKeyCredentialDescriptor(
        type: credentialMap?['type'] as String? ?? '',
        id: (credentialMap?['id'] as List?)?.cast<int>() ?? [],
      ),
      authData: (map[2] as List?)?.cast<int>() ?? [],
      signature: (map[3] as List?)?.cast<int>() ?? [],
      user: (map[4] as Map?)?.cast<String, dynamic>() != null
          ? PublicKeyCredentialUserEntity(
              id: (map[4]['id'] as List?)?.cast<int>() ?? [],
              name: map[4]['name'] as String,
              displayName: map[4]['displayName'] as String,
            )
          : null,
      numberOfCredentials: map[5] as int?,
      userSelected: map[6] as bool?,
      largeBlobKey: (map[7] as List?)?.cast<int>(),
    );
  }
} 