import 'package:cbor/cbor.dart';
import '../constants.dart';
import '../entities/credential_entities.dart';

class MakeCredentialRequest {
  final List<int> clientDataHash;
  final PublicKeyCredentialRpEntity rp;
  final PublicKeyCredentialUserEntity user;
  final List<Map<String, dynamic>> pubKeyCredParams;
  final List<PublicKeyCredentialDescriptor>? excludeList;
  final Map<String, dynamic>? extensions;
  final Map<String, bool>? options;
  final List<int>? pinAuth;
  final int? pinProtocol;
  final bool? enterpriseAttestation;
  
  MakeCredentialRequest({
    required this.clientDataHash,
    required this.rp,
    required this.user,
    required this.pubKeyCredParams,
    this.excludeList,
    this.extensions,
    this.options,
    this.pinAuth,
    this.pinProtocol,
    this.enterpriseAttestation,
  });
}

class MakeCredentialResponse {
  final String fmt;
  final List<int> authData;
  final Map<String, dynamic> attStmt;
  final bool? epAtt;
  final List<int>? largeBlobKey;
  
  MakeCredentialResponse({
    required this.fmt,
    required this.authData,
    required this.attStmt,
    this.epAtt,
    this.largeBlobKey,
  });
}

class MakeCredentialUtils {
  static List<int> makeMakeCredentialRequest(MakeCredentialRequest request) {
    final map = <int, dynamic>{};
    map[1] = CborBytes(request.clientDataHash);
    map[2] = request.rp.toCbor();
    map[3] = request.user.toCbor();
    map[4] = request.pubKeyCredParams.map((p) => CborValue(p)).toList();
    if (request.excludeList != null && request.excludeList!.isNotEmpty) {
      map[5] = request.excludeList!.map((e) => e.toCbor()).toList();
    }
    if (request.extensions != null) {
      map[6] = CborValue(request.extensions!);
    }
    if (request.options != null) {
      map[7] = CborValue(request.options!);
    }
    if (request.pinAuth != null) {
      map[8] = CborBytes(request.pinAuth!);
    }
    if (request.pinProtocol != null) {
      map[9] = request.pinProtocol!;
    }
    if (request.enterpriseAttestation != null) {
      map[10] = request.enterpriseAttestation!;
    }
    return [Ctap2Commands.makeCredential.value] + cbor.encode(CborValue(map));
  }

  static MakeCredentialResponse parseMakeCredentialResponse(List<int> data) {
    final map = cbor.decode(data).toObject() as Map;
    return MakeCredentialResponse(
      fmt: map[1] as String,
      authData: (map[2] as List?)?.cast<int>() ?? [],
      attStmt: (map[3] as Map?)?.cast<String, dynamic>() ?? {},
      epAtt: map[4] as bool?,
      largeBlobKey: (map[5] as List?)?.cast<int>(),
    );
  }
} 