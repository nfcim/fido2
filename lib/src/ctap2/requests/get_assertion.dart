import 'package:cbor/cbor.dart';
import 'package:convert/convert.dart';
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
    map[gaRpIdIdx] = CborString(rpId);
    map[gaClientDataHashIdx] = CborBytes(clientDataHash);

    if (allowList != null && allowList!.isNotEmpty) {
      map[gaAllowListIdx] = allowList!.map((a) => a.toCbor()).toList();
    }
    if (extensions != null) {
      map[gaExtensionsIdx] = CborValue(extensions!);
    }
    if (options != null) {
      map[gaOptionsIdx] = CborValue(options!);
    }
    if (pinAuth != null) {
      map[gaPinAuthIdx] = CborBytes(pinAuth!);
    }
    if (pinProtocol != null) {
      map[gaPinProtocolIdx] = pinProtocol!;
    }

    return [Ctap2Commands.getAssertion.value] + cbor.encode(CborValue(map));
  }

  @override
  String toString() {
    final buffer = StringBuffer();
    buffer.writeln('GetAssertionRequest(');
    buffer.writeln('  rpId: $rpId,');
    buffer.writeln('  clientDataHash: ${hex.encode(clientDataHash)},');

    if (allowList != null) {
      buffer.writeln('  allowList: $allowList,');
    }
    if (extensions != null) {
      buffer.writeln('  extensions: $extensions,');
    }
    if (options != null) {
      buffer.writeln('  options: $options,');
    }
    if (pinAuth != null) {
      buffer.writeln('  pinAuth: ${hex.encode(pinAuth!)},');
    }
    if (pinProtocol != null) {
      buffer.writeln('  pinProtocol: $pinProtocol,');
    }

    buffer.write(')');
    return buffer.toString();
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
    final credentialMap = map[gaRspCredentialIdx] as Map?;
    return GetAssertionResponse(
      credential: PublicKeyCredentialDescriptor(
        type: credentialMap?['type'] as String? ?? '',
        id: (credentialMap?['id'] as List?)?.cast<int>() ?? [],
      ),
      authData: (map[gaRspAuthDataIdx] as List?)?.cast<int>() ?? [],
      signature: (map[gaRspSignatureIdx] as List?)?.cast<int>() ?? [],
      user: (map[gaRspUserIdx] as Map?)?.cast<String, dynamic>() != null
          ? PublicKeyCredentialUserEntity.fromCbor(map[gaRspUserIdx])
          : null,
      numberOfCredentials: map[gaRspNumberOfCredentialsIdx] as int?,
      userSelected: map[gaRspUserSelectedIdx] as bool?,
      largeBlobKey: (map[gaRspLargeBlobKeyIdx] as List?)?.cast<int>(),
    );
  }

  @override
  String toString() {
    final buffer = StringBuffer();
    buffer.writeln('GetAssertionResponse(');
    buffer.writeln('  credential: $credential,');
    buffer.writeln('  authData: ${hex.encode(authData)},');
    buffer.writeln('  signature: ${hex.encode(signature)},');

    if (user != null) {
      buffer.writeln('  user: $user,');
    }
    if (numberOfCredentials != null) {
      buffer.writeln('  numberOfCredentials: $numberOfCredentials,');
    }
    if (userSelected != null) {
      buffer.writeln('  userSelected: $userSelected,');
    }
    if (largeBlobKey != null) {
      buffer.writeln('  largeBlobKey: ${hex.encode(largeBlobKey!)},');
    }

    buffer.write(')');
    return buffer.toString();
  }
}
