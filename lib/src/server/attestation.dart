import 'package:cbor/cbor.dart';
import '../cose.dart';
import '../crypto/crypto.dart';
import '../strict_cbor.dart';
import 'config.dart';
import 'entities/attestation.dart';
import 'entities/authenticator_data.dart';

AttestationResult verifyAttestation(
  String format,
  CborMap statement,
  AuthenticatorData data,
  List<int> clientData,
  Fido2Config config,
) {
  if (statement.tags.isNotEmpty ||
      statement.keys.any((k) => k is! CborString || k.tags.isNotEmpty)) {
    throw const FormatException('Expected untagged attestation statement');
  }
  if (format == 'none') {
    if (statement.isNotEmpty) {
      throw const FormatException(
        'None attestation requires an empty statement',
      );
    }
    return AttestationResult(
      format: format,
      type: AttestationType.none,
      aaguid: data.aaguid!,
    );
  }
  final alg = statement[CborString('alg')];
  final sig = statement[CborString('sig')];
  if (alg is! CborInt ||
      alg.tags.isNotEmpty ||
      sig is! CborBytes ||
      sig.tags.isNotEmpty ||
      sig.bytes.isEmpty ||
      statement.containsKey(CborString('ecdaaKeyId'))) {
    throw const FormatException('Invalid or unsupported packed attestation');
  }
  final algorithm = cborExactInt(alg);
  final message = [...data.bytes, ...RustCrypto.sha256(clientData)];
  final chain = statement[CborString('x5c')];
  if (chain == null) {
    final key = data.credentialPublicKey!;
    if (algorithm != key.algorithmId) {
      throw const FormatException('Packed self attestation algorithm mismatch');
    }
    key.verifySync(message, sig.bytes);
    return AttestationResult(
      format: format,
      type: AttestationType.self,
      aaguid: data.aaguid!,
    );
  }
  if (chain is! CborList || chain.tags.isNotEmpty || chain.isEmpty) {
    throw const FormatException(
      'Expected a non-empty packed x5c certificate chain',
    );
  }
  final certificates = <List<int>>[];
  for (final cert in chain) {
    if (cert is! CborBytes || cert.tags.isNotEmpty || cert.bytes.isEmpty) {
      throw const FormatException('Expected DER certificate bytes');
    }
    certificates.add(cert.bytes);
  }
  // attStmt.alg describes the certificate key, not the credential key. A
  // device can, for example, attest an Ed25519 credential with an ES256 key.
  final rustAlgorithm = switch (config.cose.resolve(algorithm)) {
    SignatureAlgorithm.es256 => 'es256',
    SignatureAlgorithm.ed25519 => 'ed25519',
    _ => throw const FormatException(
      'Unsupported packed certificate algorithm',
    ),
  };
  final List<int> key;
  try {
    key = RustCrypto.packedCertificatePublicKey(
      rustAlgorithm,
      certificates.first,
      data.aaguid!,
    );
  } on CryptoException catch (error) {
    if (error.code != 'invalid_attestation_certificate') rethrow;
    throw const FormatException('Invalid packed attestation certificate');
  }
  if (!RustCrypto.verify(
    rustAlgorithm,
    key,
    message,
    sig.bytes,
    encoding: rustAlgorithm == 'es256' ? 'der' : 'raw',
  )) {
    throw const CryptoException('invalid_signature');
  }
  return AttestationResult(
    format: format,
    type: AttestationType.basic,
    aaguid: data.aaguid!,
    trustPath: certificates,
  );
}
