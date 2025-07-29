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

  List<int> encode() {
    final map = <int, dynamic>{};
    map[mcClientDataHashIdx] = CborBytes(clientDataHash);
    map[mcRpIdx] = rp.toCbor();
    map[mcUserIdx] = user.toCbor();
    map[mcPubKeyCredParamsIdx] =
        pubKeyCredParams.map((p) => CborValue(p)).toList();
    if (excludeList != null && excludeList!.isNotEmpty) {
      map[mcExcludeListIdx] = excludeList!.map((e) => e.toCbor()).toList();
    }
    if (extensions != null) {
      map[mcExtensionsIdx] = CborValue(extensions!);
    }
    if (options != null) {
      map[mcOptionsIdx] = CborValue(options!);
    }
    if (pinAuth != null) {
      map[mcPinAuthIdx] = CborBytes(pinAuth!);
    }
    if (pinProtocol != null) {
      map[mcPinProtocolIdx] = pinProtocol!;
    }
    if (enterpriseAttestation != null) {
      map[mcEnterpriseAttestationIdx] = enterpriseAttestation!;
    }
    return [Ctap2Commands.makeCredential.value] + cbor.encode(CborValue(map));
  }
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

  static MakeCredentialResponse decode(List<int> data) {
    final map = cbor.decode(data).toObject() as Map;
    return MakeCredentialResponse(
      fmt: map[mcRspFmtIdx] as String,
      authData: (map[mcRspAuthDataIdx] as List?)?.cast<int>() ?? [],
      attStmt: (map[mcRspAttStmtIdx] as Map?)?.cast<String, dynamic>() ?? {},
      epAtt: map[mcRspEpAttIdx] as bool?,
      largeBlobKey: (map[mcRspLargeBlobKeyIdx] as List?)?.cast<int>(),
    );
  }
}
