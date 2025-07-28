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

  List<int> encode() {
    final map = <int, dynamic>{};
    map[1] = CborString(rpId);
    map[2] = CborBytes(clientDataHash);

    if (allowList != null && allowList!.isNotEmpty) {
      map[3] = allowList!.map((a) => a.toCbor()).toList();
    }
    if (extensions != null) {
      map[4] = CborValue(extensions!);
    }
    if (options != null) {
      map[5] = CborValue(options!);
    }
    if (pinAuth != null) {
      map[6] = CborBytes(pinAuth!);
    }
    if (pinProtocol != null) {
      map[7] = pinProtocol!;
    }

    return [Ctap2Commands.getAssertion.value] + cbor.encode(CborValue(map));
  }
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

  static GetAssertionResponse decode(List<int> data) {
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
          ? PublicKeyCredentialUserEntity.fromCbor(map[4])
          : null,
      numberOfCredentials: map[5] as int?,
      userSelected: map[6] as bool?,
      largeBlobKey: (map[7] as List?)?.cast<int>(),
    );
  }
}
