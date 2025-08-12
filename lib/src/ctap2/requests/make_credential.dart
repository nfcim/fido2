import 'package:cbor/cbor.dart';
import 'package:convert/convert.dart';
import '../constants.dart';
import '../entities/credential_entities.dart';

class MakeCredentialRequest {
  static const int clientDataHashIdx = 1;
  static const int rpIdx = 2;
  static const int userIdx = 3;
  static const int pubKeyCredParamsIdx = 4;
  static const int excludeListIdx = 5;
  static const int extensionsIdx = 6;
  static const int optionsIdx = 7;
  static const int pinAuthIdx = 8;
  static const int pinProtocolIdx = 9;
  static const int enterpriseAttestationIdx = 10;

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
    map[clientDataHashIdx] = CborBytes(clientDataHash);
    map[rpIdx] = rp.toCbor();
    map[userIdx] = user.toCbor();
    map[pubKeyCredParamsIdx] =
        pubKeyCredParams.map((p) => CborValue(p)).toList();
    if (excludeList != null && excludeList!.isNotEmpty) {
      map[excludeListIdx] = excludeList!.map((e) => e.toCbor()).toList();
    }
    if (extensions != null) {
      map[extensionsIdx] = CborValue(extensions!);
    }
    if (options != null) {
      map[optionsIdx] = CborValue(options!);
    }
    if (pinAuth != null) {
      map[pinAuthIdx] = CborBytes(pinAuth!);
    }
    if (pinProtocol != null) {
      map[pinProtocolIdx] = pinProtocol!;
    }
    if (enterpriseAttestation != null) {
      map[enterpriseAttestationIdx] = enterpriseAttestation!;
    }
    return [Ctap2Commands.makeCredential.value] + cbor.encode(CborValue(map));
  }

  @override
  String toString() {
    final buffer = StringBuffer();
    buffer.writeln('MakeCredentialRequest(');
    buffer.writeln('  clientDataHash: ${hex.encode(clientDataHash)},');
    buffer.writeln('  rp: $rp,');
    buffer.writeln('  user: $user,');
    buffer.writeln('  pubKeyCredParams: $pubKeyCredParams,');

    if (excludeList != null) {
      buffer.writeln('  excludeList: $excludeList,');
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
    if (enterpriseAttestation != null) {
      buffer.writeln('  enterpriseAttestation: $enterpriseAttestation,');
    }

    buffer.write(')');
    return buffer.toString();
  }
}

class MakeCredentialResponse {
  static const int fmtIdx = 1;
  static const int authDataIdx = 2;
  static const int attStmtIdx = 3;
  static const int epAttIdx = 4;
  static const int largeBlobKeyIdx = 5;

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
      fmt: map[fmtIdx] as String,
      authData: (map[authDataIdx] as List?)?.cast<int>() ?? [],
      attStmt: (map[attStmtIdx] as Map?)?.cast<String, dynamic>() ?? {},
      epAtt: map[epAttIdx] as bool?,
      largeBlobKey: (map[largeBlobKeyIdx] as List?)?.cast<int>(),
    );
  }

  @override
  String toString() {
    final buffer = StringBuffer();
    buffer.writeln('MakeCredentialResponse(');
    buffer.writeln('  fmt: $fmt,');
    buffer.writeln('  authData: ${hex.encode(authData)},');
    buffer.writeln('  attStmt: $attStmt,');

    if (epAtt != null) {
      buffer.writeln('  epAtt: $epAtt,');
    }
    if (largeBlobKey != null) {
      buffer.writeln('  largeBlobKey: ${hex.encode(largeBlobKey!)},');
    }

    buffer.write(')');
    return buffer.toString();
  }
}
